import { createHash, randomBytes } from "crypto";
import Long from "long";
import { Message, Properties } from "protobufjs/light";
import { CalypsoWriteInstance, Write } from "../../calypso/calypso-instance";
import { LongTermSecret } from "../../calypso/calypso-rpc";
import { IIdentity } from "../../darc";
import Darc from "../../darc/darc";
import Signer from "../../darc/signer";
import ISigner from "../../darc/signer";
import { Log } from "../../log";
import { PopPartyInstance } from "../../personhood/pop-party-instance";
import { PopDesc } from "../../personhood/proto";
import RoPaSciInstance, { RoPaSciStruct } from "../../personhood/ro-pa-sci-instance";
import { registerMessage } from "../../protobuf";
import ByzCoinRPC from "../byzcoin-rpc";
import ClientTransaction, { Argument, Instruction } from "../client-transaction";
import Instance, { InstanceID } from "../instance";
import CoinInstance, { Coin } from "./coin-instance";
import CredentialInstance from "./credentials-instance";
import CredentialsInstance, { CredentialStruct } from "./credentials-instance";
import DarcInstance, { newDarc } from "./darc-instance";

export const SPAWNER_COIN = Buffer.alloc(32, 0);
SPAWNER_COIN.write("SpawnerCoin");

export default class SpawnerInstance extends Instance {

    /**
     * Get the total cost required to sign up
     *
     * @returns the cost
     */
    get signupCost(): Long {
        return this.struct.costCoin.value
            .add(this.struct.costDarc.value)
            .add(this.struct.costCredential.value);
    }

    static readonly contractID = "spawner";

    /**
     * Spawn a spawner instance. It takes either an ICreateSpawner as single argument, or all the arguments
     * separated.
     *
     * @param params The ByzCoinRPC to use or an ICreateSpawner
     * @param darcID The darc instance ID
     * @param signers The list of signers
     * @param costs The different cost for new instances
     * @param beneficiary The beneficiary of the costs
     */
    static async spawn(params: ICreateSpawner | ByzCoinRPC, darcID?: InstanceID, signers?: Signer[],
                       costs?: ICreateCost,
                       beneficiary?: InstanceID): Promise<SpawnerInstance> {
        let bc: ByzCoinRPC;
        if (params instanceof ByzCoinRPC) {
            bc = params as ByzCoinRPC;
        } else {
            ({bc, darcID, signers, costs, beneficiary } = params as ICreateSpawner);
        }

        const args = [
            ...Object.keys(costs).map((k: string) => {
                const value = new Coin({name: SPAWNER_COIN, value: costs[k]}).toBytes();
                return new Argument({name: k, value});
            }),
            new Argument({name: "beneficiary", value: beneficiary}),
        ];

        const inst = Instruction.createSpawn(darcID, this.contractID, args);
        const ctx = new ClientTransaction({instructions: [inst]});
        await ctx.updateCountersAndSign(bc, [signers]);

        await bc.sendTransactionAndWait(ctx);

        return this.fromByzcoin(bc, inst.deriveId());
    }

    /**
     * Initializes using an existing coinInstance from ByzCoin
     *
     * @param bc an initialized byzcoin RPC instance
     * @param iid the instance-ID of the spawn-instance
     */
    static async fromByzcoin(bc: ByzCoinRPC, iid: InstanceID): Promise<SpawnerInstance> {
        const proof = await bc.getProof(iid, 2);
        if (!proof.exists(iid)) {
            throw new Error("fail to get a matching proof");
        }

        return new SpawnerInstance(bc, await proof.getVerifiedInstance(bc.genesisID,
            SpawnerInstance.contractID));
    }
    private struct: SpawnerStruct;

    /**
     * Creates a new SpawnerInstance
     * @param bc        The ByzCoinRPC instance
     * @param iid       The instance ID
     * @param spawner   Parameters for the spawner: costs and names
     */
    constructor(private rpc: ByzCoinRPC, inst: Instance) {
        super(inst);
        if (inst.contractID.toString() !== SpawnerInstance.contractID) {
            throw new Error(`mismatch contract name: ${inst.contractID} vs ${SpawnerInstance.contractID}`);
        }

        this.struct = SpawnerStruct.decode(inst.data);
    }

    /**
     * Update the data of this instance
     *
     * @returns a promise that resolves once the data is up-to-date
     */
    async update(): Promise<SpawnerInstance> {
        const proof = await this.rpc.getProof(this.id);
        this.struct = SpawnerStruct.decode(proof.value);
        return this;
    }

    /**
     * Create a darc for a user
     *
     * @param coin      The coin instance to take coins from
     * @param signers   The signers for the transaction
     * @param darcs... All the darcs to spawn using the spawner. The coin instance must have enough
     * coins to pay for all darcs.
     * @returns a promise that resolves with the new array of the instantiated darc instances
     */
    async spawnDarc(coin: CoinInstance, signers: Signer[], ...darcs: Darc[]): Promise<DarcInstance[]> {
        const cost = this.struct.costDarc.value.mul(darcs.length);
        const ctx = new ClientTransaction({
            instructions: [
                Instruction.createInvoke(
                    coin.id,
                    CoinInstance.contractID,
                    CoinInstance.commandFetch,
                    [new Argument({name: CoinInstance.argumentCoins, value: Buffer.from(cost.toBytesLE())})],
                ),
            ],
        });
        darcs.forEach((darc) => {
            ctx.instructions.push(
                Instruction.createSpawn(
                    this.id,
                    DarcInstance.contractID,
                    [new Argument({name: DarcInstance.argumentDarc, value: darc.toBytes()})],
                ));
        });
        await ctx.updateCountersAndSign(this.rpc, [signers]);

        await this.rpc.sendTransactionAndWait(ctx);

        const dis = [];
        for (const da of darcs) {
            for (let i = 0; i < 10; i++) {
                try {
                    dis.push(await DarcInstance.fromByzcoin(this.rpc, da.getBaseID()));
                    break;
                } catch (e) {
                    Log.warn("couldn't get proof - perhaps still updating?");
                }
            }
        }
        return dis;
    }

    /**
     * Create a coin instance for a given darc
     *
     * @param coin      The coin instance to take the coins from
     * @param signers   The signers for the transaction
     * @param darcID    The darc responsible for this coin
     * @param coinID    The instance-ID for the coin - will be calculated as sha256("coin" | coinID)
     * @param balance   The starting balance
     * @returns a promise that resolves with the new coin instance
     */
    async spawnCoin(coin: CoinInstance, signers: Signer[], darcID: InstanceID, coinID: Buffer, balance?: Long):
        Promise<CoinInstance> {

        balance = balance || Long.fromNumber(0);
        const valueBuf = this.struct.costCoin.value.add(balance).toBytesLE();
        const ctx = new ClientTransaction({
            instructions: [
                Instruction.createInvoke(
                    coin.id,
                    CoinInstance.contractID,
                    CoinInstance.commandFetch,
                    [new Argument({name: CoinInstance.argumentCoins, value: Buffer.from(valueBuf)})],
                ),
                Instruction.createSpawn(
                    this.id,
                    CoinInstance.contractID,
                    [
                        new Argument({name: "coinName", value: SPAWNER_COIN}),
                        new Argument({name: "coinID", value: coinID}),
                        new Argument({name: "darcID", value: darcID}),
                    ],
                ),
            ],
        });
        await ctx.updateCountersAndSign(this.rpc, [signers, []]);
        await this.rpc.sendTransactionAndWait(ctx);

        return CoinInstance.fromByzcoin(this.rpc, CoinInstance.coinIID(coinID));
    }

    /**
     * Create a credential instance for the given darc
     *
     * @param coin      The coin instance to take coins from
     * @param signers   The signers for the transaction
     * @param darcID    The darc instance ID
     * @param cred      The starting credentials
     * @param credID    The instance-ID for this credential - will be calculated as sha256("credential" | credID)
     * @returns a promise that resolves with the new credential instance
     */
    async spawnCredential(
        coin: CoinInstance,
        signers: ISigner[],
        darcID: Buffer,
        cred: CredentialStruct,
        credID: Buffer = null,
    ): Promise<CredentialsInstance> {
        const valueBuf = this.struct.costCredential.value.toBytesLE();
        const credArgs = [
            new Argument({name: CredentialsInstance.argumentDarcID, value: darcID}),
            new Argument({name: CredentialsInstance.argumentCredential, value: cred.toBytes()}),
        ];
        let finalCredID: Buffer;
        if (credID) {
            credArgs.push(new Argument({name: CredentialsInstance.argumentCredID, value: credID}));
            finalCredID = CredentialInstance.credentialIID(credID);
        } else {
            finalCredID = CredentialsInstance.credentialIID(darcID);
        }
        const ctx = new ClientTransaction({
            instructions: [
                Instruction.createInvoke(
                    coin.id,
                    CoinInstance.contractID,
                    CoinInstance.commandFetch,
                    [new Argument({name: CoinInstance.argumentCoins, value: Buffer.from(valueBuf)})],
                ),
                Instruction.createSpawn(
                    this.id,
                    CredentialInstance.contractID,
                    credArgs,
                ),
            ],
        });
        await ctx.updateCountersAndSign(this.rpc, [signers, []]);
        await this.rpc.sendTransactionAndWait(ctx);

        return CredentialInstance.fromByzcoin(this.rpc, finalCredID);
    }

    /**
     * Create a PoP party
     *
     * @param coin The coin instance to take coins from
     * @param signers The signers for the transaction
     * @param orgs The list fo organisers
     * @param descr The data for the PoP party
     * @param reward The reward of an attendee
     * @returns a promise tha resolves with the new pop party instance
     */
    async spawnPopParty(params: ICreatePopParty): Promise<PopPartyInstance> {
        const {coin, signers, orgs, desc, reward} = params;

        // Verify that all organizers have published their personhood public key
        for (const org of orgs) {
            if (!org.getAttribute("personhood", "ed25519")) {
                throw new Error(`One of the organisers didn't publish his personhood key`);
            }
        }

        const orgDarcIDs = orgs.map((org) => org.darcID);
        const valueBuf = this.struct.costDarc.value.add(this.struct.costParty.value).toBytesLE();
        const orgDarc = PopPartyInstance.preparePartyDarc(orgDarcIDs, "party-darc " + desc.name);
        const ctx = new ClientTransaction({
            instructions: [
                Instruction.createInvoke(
                    coin.id,
                    CoinInstance.contractID,
                    CoinInstance.commandFetch,
                    [new Argument({name: CoinInstance.argumentCoins, value: Buffer.from(valueBuf)})],
                ),
                Instruction.createSpawn(
                    this.id,
                    DarcInstance.contractID,
                    [new Argument({name: DarcInstance.argumentDarc, value: orgDarc.toBytes()})],
                ),
                Instruction.createSpawn(
                    this.id,
                    PopPartyInstance.contractID,
                    [
                        new Argument({name: "darcID", value: orgDarc.getBaseID()}),
                        new Argument({name: "description", value: desc.toBytes()}),
                        new Argument({name: "miningReward", value: Buffer.from(reward.toBytesLE())}),
                    ],
                ),
            ],
        });
        await ctx.updateCountersAndSign(this.rpc, [signers, [], []]);

        await this.rpc.sendTransactionAndWait(ctx);

        return PopPartyInstance.fromByzcoin(this.rpc, ctx.instructions[2].deriveId());
    }

    /**
     * Create a Rock-Paper-Scisors game instance
     *
     * @param desc      The description of the game
     * @param coin      The coin instance to take coins from
     * @param signers   The list of signers
     * @param stake     The reward for the winner
     * @param choice    The choice of the first player
     * @param fillup    Data that will be hash with the choice
     * @returns a promise that resolves with the new instance
     */
    async spawnRoPaSci(params: ICreateRoPaSci): Promise<RoPaSciInstance> {
        const {desc, coin, signers, stake, choice, fillup} = params;

        if (fillup.length !== 31) {
            throw new Error("need exactly 31 bytes for fillUp");
        }

        const c = new Coin({name: coin.coin.name, value: stake.add(this.struct.costRoPaSci.value)});
        if (coin.coin.value.lessThan(c.value)) {
            throw new Error("account balance not high enough for that stake");
        }

        const fph = createHash("sha256");
        fph.update(Buffer.from([choice % 3]));
        fph.update(fillup);
        const rps = new RoPaSciStruct({
            description: desc,
            firstPlayer: -1,
            firstPlayerHash: fph.digest(),
            secondPlayer: -1,
            secondPlayerAccount: Buffer.alloc(32),
            stake: c,
        });

        const ctx = new ClientTransaction({
            instructions: [
                Instruction.createInvoke(
                    coin.id,
                    CoinInstance.contractID,
                    CoinInstance.commandFetch,
                    [new Argument({name: CoinInstance.argumentCoins, value: Buffer.from(c.value.toBytesLE())})],
                ),
                Instruction.createSpawn(
                    this.id,
                    RoPaSciInstance.contractID,
                    [new Argument({name: "struct", value: rps.toBytes()})],
                ),
            ],
        });
        await ctx.updateCountersAndSign(this.rpc, [signers, []]);

        await this.rpc.sendTransactionAndWait(ctx);

        const rpsi = await RoPaSciInstance.fromByzcoin(this.rpc, ctx.instructions[1].deriveId());
        rpsi.setChoice(choice, fillup);

        return rpsi;
    }

    async spawnCalypsoWrite(coinInst: CoinInstance, signers: Signer[], lts: LongTermSecret, key: Buffer,
                            ident: IIdentity[], data?: Buffer):
        Promise<CalypsoWriteInstance> {

        if (coinInst.coin.value.lessThan(this.struct.costDarc.value.add(this.struct.costCWrite.value))) {
            throw new Error("account balance not high enough for spawning a darc + calypso writer");
        }

        const cwDarc = newDarc([ident[0]], ident,
            Buffer.from("calypso write protection " + randomBytes(8).toString("hex")),
            ["spawn:calypsoRead"]);
        const d = await this.spawnDarc(coinInst, signers, cwDarc);

        const write = await Write.createWrite(lts.id, d[0].id, lts.X, key);
        write.cost = this.struct.costCRead;
        if (data) {
            write.data = data;
        }

        const ctx = new ClientTransaction({
            instructions: [
                Instruction.createInvoke(coinInst.id, CoinInstance.contractID, CoinInstance.commandFetch, [
                    new Argument({name: CoinInstance.argumentCoins,
                        value: Buffer.from(this.struct.costCWrite.value.toBytesLE())}),
                ]),
                Instruction.createSpawn(this.id, CalypsoWriteInstance.contractID, [
                    new Argument({name: CalypsoWriteInstance.argumentWrite,
                        value: Buffer.from(Write.encode(write).finish())}),
                    new Argument({name: "darcID", value: d[0].id}),
                ]),
            ],
        });
        await ctx.updateCountersAndSign(this.rpc, [signers, []]);
        await this.rpc.sendTransactionAndWait(ctx);

        return CalypsoWriteInstance.fromByzcoin(this.rpc, ctx.instructions[1].deriveId());
    }
}

/**
 * Data of a spawner instance
 */
export class SpawnerStruct extends Message<SpawnerStruct> {

    /**
     * @see README#Message classes
     */
    static register() {
        registerMessage("personhood.SpawnerStruct", SpawnerStruct, Coin);
    }

    readonly costDarc: Coin;
    readonly costCoin: Coin;
    readonly costCredential: Coin;
    readonly costParty: Coin;
    readonly costRoPaSci: Coin;
    readonly costCWrite: Coin;
    readonly costCRead: Coin;
    readonly beneficiary: InstanceID;

    constructor(props?: Properties<SpawnerStruct>) {
        super(props);

        /* Protobuf aliases */

        Object.defineProperty(this, "costdarc", {
            get(): Coin {
                return this.costDarc;
            },
            set(value: Coin) {
                this.costDarc = value;
            },
        });

        Object.defineProperty(this, "costcoin", {
            get(): Coin {
                return this.costCoin;
            },
            set(value: Coin) {
                this.costCoin = value;
            },
        });

        Object.defineProperty(this, "costcredential", {
            get(): Coin {
                return this.costCredential;
            },
            set(value: Coin) {
                this.costCredential = value;
            },
        });

        Object.defineProperty(this, "costparty", {
            get(): Coin {
                return this.costParty;
            },
            set(value: Coin) {
                this.costParty = value;
            },
        });

        Object.defineProperty(this, "costropasci", {
            get(): Coin {
                return this.costRoPaSci;
            },
            set(value: Coin) {
                this.costRoPaSci = value;
            },
        });

        Object.defineProperty(this, "costcread", {
            get(): Coin {
                return this.costCRead;
            },
            set(value: Coin) {
                this.costCRead = value;
            },
        });
        Object.defineProperty(this, "costcwrite", {
            get(): Coin {
                return this.costCWrite;
            },
            set(value: Coin) {
                this.costCWrite = value;
            },
        });
    }
}

/**
 * Fields of the costs of a spawner instance
 */
interface ICreateCost {
    costCRead: Long;
    costCWrite: Long;
    costCoin: Long;
    costCredential: Long;
    costDarc: Long;
    costParty: Long;

    [k: string]: Long;
}

/**
 * Parameters to create a spawner instance
 */
interface ICreateSpawner {
    bc: ByzCoinRPC;
    darcID: InstanceID;
    signers: Signer[];
    costs: ICreateCost;
    beneficiary: InstanceID;

    [k: string]: any;
}

/**
 * Parameters to create a rock-paper-scisors game
 */
interface ICreateRoPaSci {
    desc: string;
    coin: CoinInstance;
    signers: Signer[];
    stake: Long;
    choice: number;
    fillup: Buffer;

    [k: string]: any;
}

/**
 * Parameters to create a pop party
 */
interface ICreatePopParty {
    coin: CoinInstance;
    signers: Signer[];
    orgs: CredentialInstance[];
    desc: PopDesc;
    reward: Long;

    [k: string]: any;
}

/**
 * Parameters to create a rock-paper-scisors game
 */
interface ISpawnCalyspoWrite {
    coin: CoinInstance;
    signers: Signer[];
    write: Write;
    darcID: InstanceID;
    choice: number;

    [k: string]: any;
}

SpawnerStruct.register();

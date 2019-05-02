import { createHash } from "crypto";
import Long from "long";
import { IIdentity } from "../../darc";
import Darc from "../../darc/darc";
import Rules from "../../darc/rules";
import Signer from "../../darc/signer";
import { Log } from "../../log";
import ByzCoinRPC from "../byzcoin-rpc";
import ClientTransaction, { Argument, Instruction } from "../client-transaction";
import Instance, { InstanceID } from "../instance";

export default class DarcInstance extends Instance {
    static readonly contractID = "darc";
    static readonly commandSign = "_sign";
    static readonly commandEvolve = "evolve";
    static readonly argumentDarc = "darc";

    /**
     * Initializes using an existing coinInstance from ByzCoin
     *
     * @param bc a working ByzCoin instance
     * @param iid the instance id of the darc-instance
     */
    static async fromByzcoin(bc: ByzCoinRPC, iid: Buffer): Promise<DarcInstance> {
        return new DarcInstance(bc, await Instance.fromByzCoin(bc, iid));
    }

    /**
     * spawn creates a new darc, given a darcID.
     *
     * @param rpc a working ByzCoin instance
     * @param darcID a darc that has the right to spawn new darcs
     * @param signers fulfilling the `spawn:darc` rule of the darc pointed to by darcID
     * @param newD the new darc to spawn
     */
    static async spawn(rpc: ByzCoinRPC,
                       darcID: InstanceID,
                       signers: Signer[],
                       newD: Darc): Promise<DarcInstance> {
        const di = await DarcInstance.fromByzcoin(rpc, darcID);
        return di.spawnDarcAndWait(newD, signers, 10);
    }

    /**
     * create returns a DarcInstance, given a ByzCoin and a darc. The instance must already exist on
     * ByzCoin. This method does not verify if it does or not.
     *
     * @param rpc a working ByzCoin instance
     * @param d the darc
     */
    static create(rpc: ByzCoinRPC,
                  d: Darc): DarcInstance {
        return new DarcInstance(rpc, Instance.fromFields(d.getBaseID(), DarcInstance.contractID, d.getBaseID(),
            d.toBytes()));
    }

    darc: Darc;

    constructor(private rpc: ByzCoinRPC, inst: Instance) {
        super(inst);
        if (inst.contractID.toString() !== DarcInstance.contractID) {
            throw new Error(`mismatch contract name: ${inst.contractID} vs ${DarcInstance.contractID}`);
        }

        this.darc = Darc.decode(inst.data);
    }

    /**
     * Update the data of this instance
     *
     * @return a promise that resolves once the data is up-to-date
     */
    async update(): Promise<DarcInstance> {
        const proof = await this.rpc.getProof(this.darc.getBaseID());
        const inst = await proof.getVerifiedInstance(this.rpc.getGenesis().computeHash(), DarcInstance.contractID);
        this.darc = Darc.decode(inst.data);

        return this;
    }

    getSignerExpression(): Buffer {
        for (const rule of this.darc.rules.list) {
            if (rule.action === DarcInstance.commandSign) {
                return rule.expr;
            }
        }
        throw new Error("This darc doesn't have a sign expression");
    }

    getSignerDarcIDs(): InstanceID[] {
        const expr = this.getSignerExpression().toString();
        if (expr.match(/\(&/)) {
            throw new Error('Don\'t know what to do with "(" or "&" in expression');
        }
        const ret: InstanceID[] = [];
        expr.split("|").forEach((exp) => {
            if (exp.startsWith("darc:")) {
                ret.push(Buffer.from(exp.slice(5), "hex"));
            } else {
                Log.warn("Non-darc expression in signer:", exp);
            }
        });
        return ret;
    }

    /**
     * Request to evolve the existing darc using the new darc and wait for
     * the block inclusion
     *
     * @param newD The new darc
     * @param signers Signers for the counters
     * @param wait Number of blocks to wait for
     * @returns a promise that resolves with the new darc instance
     */
    async evolveDarcAndWait(newD: Darc, signers: Signer[], wait: number): Promise<DarcInstance> {
        if (!newD.getBaseID().equals(this.darc.getBaseID())) {
            throw new Error("not the same base id for the darc");
        }
        if (newD.version.compare(this.darc.version.add(1)) !== 0) {
            throw new Error("not the right version");
        }
        if (!newD.prevID.equals(this.darc.id)) {
            throw new Error("doesn't point to the previous darc");
        }
        const args = [new Argument({name: DarcInstance.argumentDarc,
            value: Buffer.from(Darc.encode(newD).finish())})];
        const instr = Instruction.createInvoke(this.darc.getBaseID(),
            DarcInstance.contractID, DarcInstance.commandEvolve, args);

        const ctx = new ClientTransaction({instructions: [instr]});
        await ctx.updateCounters(this.rpc, [signers]);
        ctx.signWith([signers]);

        await this.rpc.sendTransactionAndWait(ctx, wait);

        return this.update();
    }

    /**
     * Request to spawn an instance and wait for the inclusion
     *
     * @param d             The darc to spawn
     * @param signers       Signers for the counters
     * @param wait          Number of blocks to wait for
     * @returns a promise that resolves with the new darc instance
     */
    async spawnDarcAndWait(d: Darc, signers: Signer[], wait: number = 0): Promise<DarcInstance> {
        await this.spawnInstanceAndWait(DarcInstance.contractID,
            [new Argument({
                name: DarcInstance.argumentDarc,
                value: Buffer.from(Darc.encode(d).finish()),
            })], signers, wait);
        return DarcInstance.fromByzcoin(this.rpc, d.getBaseID());
    }

    /**
     * Request to spawn an instance of any contract and wait
     *
     * @param contractID    Contract name of the new instance
     * @param signers       Signers for the counters
     * @param wait          Number of blocks to wait for
     * @returns a promise that resolves with the instanceID of the new instance, which is only valid if the
     *          contract.spawn uses DeriveID.
     */
    async spawnInstanceAndWait(contractID: string, args: Argument[], signers: Signer[], wait: number = 0):
        Promise<InstanceID> {
        const instr = Instruction.createSpawn(this.darc.getBaseID(), DarcInstance.contractID, args);

        const ctx = new ClientTransaction({instructions: [instr]});
        await ctx.updateCounters(this.rpc, [signers]);
        ctx.signWith([signers]);

        await this.rpc.sendTransactionAndWait(ctx, wait);

        return ctx.instructions[0].deriveId();
    }
}

/**
 * Create a list of rules with basic permissions for owners and signers
 * @param owners those allow to evolve the darc
 * @param signers those allow to sign
 * @returns the list of rules
 */
export function initRules(owners: IIdentity[], signers: IIdentity[]): Rules {
    const rules = new Rules();

    owners.forEach((o) => rules.appendToRule("invoke:darc.evolve", o, Rules.AND));
    signers.forEach((s) => rules.appendToRule(DarcInstance.commandSign, s, Rules.OR));

    return rules;
}

/**
 * Create a genesis darc using the owners and signers to populate the
 * rules.
 * @param owners    those you can evolve the darc
 * @param signers   those you can sign
 * @param desc      the description of the darc
 * @returns the new darc
 */
export function newDarc(owners: IIdentity[], signers: IIdentity[], desc?: Buffer, rules?: string[]): Darc {
    const darc = new Darc({
        baseID: Buffer.from([]),
        description: desc,
        prevID: createHash("sha256").digest(),
        rules: initRules(owners, signers),
        version: Long.fromNumber(0, true),
    });
    if (rules) {
        rules.forEach((r) => {
            signers.forEach((s) => {
                darc.rules.appendToRule(r, s, "|");
            });
        });
    }

    return darc;
}

import { Point } from "@dedis/kyber";
import { createHash, randomBytes } from "crypto";
import { Message, Properties } from "protobufjs/light";
import Signer from "../../darc/signer";
import { EMPTY_BUFFER, registerMessage } from "../../protobuf";
import ByzCoinRPC from "../byzcoin-rpc";
import ClientTransaction, { Argument, Instruction } from "../client-transaction";
import Instance, { InstanceID } from "../instance";

export default class CredentialsInstance extends Instance {
    static readonly contractID = "credential";
    static readonly commandUpdate = "update";
    static readonly argumentCredential = "credential";
    static readonly argumentCredID = "credID";
    static readonly argumentDarcID = "darcID";

    /**
     * Generate the credential instance ID for a given darc ID
     *
     * @param buf The base ID of the darc
     * @returns the id as a buffer
     */
    static credentialIID(buf: Buffer): InstanceID {
        const h = createHash("sha256");
        h.update(Buffer.from(CredentialsInstance.contractID));
        h.update(buf);
        return h.digest();
    }

    /**
     * Spawn a new credential instance from a darc
     *
     * @param bc        The RPC to use
     * @param darcID    The darc instance ID
     * @param signers   The list of signers for the transaction
     * @param cred      The credential to store
     * @param credID       Optional - if given, the instanceID will be sha256("credential" | pub)
     * @param did       Optional - if given, replaces the responsible darc with the given did
     * @returns a promise that resolves with the new instance
     */
    static async spawn(
        bc: ByzCoinRPC,
        darcID: InstanceID,
        signers: Signer[],
        cred: CredentialStruct,
        credID: Buffer = null,
        did: InstanceID = null,
    ): Promise<CredentialsInstance> {
        const args = [new Argument({name: CredentialsInstance.argumentCredential, value: cred.toBytes()})];
        if (credID) {
            args.push(new Argument({name: CredentialsInstance.argumentCredID, value: credID}));
        }
        if (did) {
            args.push(new Argument({name: CredentialsInstance.argumentDarcID, value: did}));
        }
        const inst = Instruction.createSpawn(
            darcID,
            CredentialsInstance.contractID,
            args,
        );
        await inst.updateCounters(bc, signers);

        const ctx = new ClientTransaction({instructions: [inst]});
        ctx.signWith([signers]);

        await bc.sendTransactionAndWait(ctx, 10);

        return CredentialsInstance.fromByzcoin(bc, inst.deriveId());
    }

    /**
     * Create a new credential instance from a darc
     *
     * @param bc        The RPC to use
     * @param darcID    The darc instance ID
     * @param cred      The credential to store
     * @param credID       Optional - if given, the instanceID will be sha256("credential" | credID)
     * @returns a promise that resolves with the new instance
     */
    static create(
        bc: ByzCoinRPC,
        darcID: InstanceID,
        cred: CredentialStruct,
        credID: Buffer = null,
    ): CredentialsInstance {
        if (!credID) {
            credID = randomBytes(32);
        }
        return new CredentialsInstance(bc, Instance.fromFields(CredentialsInstance.credentialIID(credID),
            CredentialsInstance.contractID, darcID, cred.toBytes()));
    }

    /**
     * Get an existing credential instance using its instance ID by fetching
     * the proof.
     * @param bc    the byzcoin RPC
     * @param iid   the instance ID
     */
    static async fromByzcoin(bc: ByzCoinRPC, iid: InstanceID): Promise<CredentialsInstance> {
        return new CredentialsInstance(bc, await Instance.fromByzCoin(bc, iid));
    }
    credential: CredentialStruct;

    constructor(private rpc: ByzCoinRPC, inst: Instance) {
        super(inst);
        if (inst.contractID.toString() !== CredentialsInstance.contractID) {
            throw new Error(`mismatch contract name: ${inst.contractID} vs ${CredentialsInstance.contractID}`);
        }
        this.credential = CredentialStruct.decode(inst.data);
    }

    /**
     * Update the data of the crendetial instance by fetching the proof
     *
     * @returns a promise resolving with the instance on success, rejecting with
     * the error otherwise
     */
    async update(): Promise<CredentialsInstance> {
        const inst = await Instance.fromByzCoin(this.rpc, this.id);
        this.data = inst.data;
        this.credential = CredentialStruct.decode(this.data);
        return this;
    }

    /**
     * Get a credential attribute
     *
     * @param credential    The name of the credential
     * @param attribute     The name of the attribute
     * @returns the value of the attribute if it exists, null otherwise
     */
    getAttribute(credential: string, attribute: string): Buffer {
        return this.credential.getAttribute(credential, attribute);
    }

    /**
     * Set or update a credential attribute locally. The new credential is not sent to
     * the blockchain, for this you need to call sendUpdate.
     *
     * @param credential    Name of the credential
     * @param attribute     Name of the attribute
     * @param value         The value to set
     * @returns a promise resolving when the transaction is in a block, or rejecting
     * for an error
     */
    async setAttribute(credential: string, attribute: string, value: Buffer): Promise<any> {
        return this.credential.setAttribute(credential, attribute, value);
    }

    async sendUpdate(owners: Signer[], newCred: CredentialStruct = null): Promise<CredentialsInstance> {
        if (newCred) {
            this.credential = newCred.copy();
        }
        const instr = Instruction.createInvoke(
            this.id,
            CredentialsInstance.contractID,
            CredentialsInstance.commandUpdate,
            [new Argument({name: CredentialsInstance.argumentCredential, value: this.credential.toBytes()})],
        );
        const ctx = new ClientTransaction({instructions: [instr]});
        await ctx.updateCountersAndSign(this.rpc, [owners]);

        await this.rpc.sendTransactionAndWait(ctx);

        return this;
    }

    async recoverIdentity(pubKey: Point, signatures: RecoverySignature[]): Promise<any> {
        const sigBuf = Buffer.alloc(RecoverySignature.pubSig * signatures.length);
        signatures.forEach((s, i) => s.signature.copy(sigBuf, RecoverySignature.pubSig * i));
        const ctx = new ClientTransaction({
            instructions: [
                Instruction.createInvoke(
                    this.id,
                    CredentialsInstance.contractID,
                    "recover",
                    [new Argument({name: "signatures", value: sigBuf}),
                        new Argument({name: "public", value: pubKey.toProto()})]),
            ],
        });
        await this.rpc.sendTransactionAndWait(ctx);
    }
}

/**
 * Data of a credential instance. It contains none, one or multiple
 * credentials.
 */
export class CredentialStruct extends Message<CredentialStruct> {

    /**
     * @see README#Message classes
     */
    static register() {
        registerMessage("personhood.CredentialStruct", CredentialStruct, Credential);
    }

    readonly credentials: Credential[];

    constructor(properties?: Properties<CredentialStruct>) {
        super(properties);

        this.credentials = this.credentials.slice() || [];
    }

    /**
     * Get a credential attribute
     *
     * @param credential    The name of the credential
     * @param attribute     The name of the attribute
     * @returns the value of the attribute if it exists, null otherwise
     */
    getAttribute(credential: string, attribute: string): Buffer {
        const cred = this.credentials.find((c) => c.name === credential);
        if (!cred) {
            return null;
        }
        const att = cred.attributes.find((a) => a.name === attribute);
        if (!att) {
            return null;
        }
        return att.value;
    }

    /**
     * getCredential returns the credential with the given name, or null if
     * nothing found.
     * @param credential name of the credential to return
     */
    getCredential(credential: string): Credential {
        return this.credentials.find((c) => c.name === credential);
    }

    /**
     * Set or update a credential attribute locally. The update is not sent to the blockchain.
     * For this you need to call CredentialInstance.sendUpdate().
     *
     * @param owner         Signer to use for the transaction
     * @param credential    Name of the credential
     * @param attribute     Name of the attribute
     * @param value         The value to set
     * @returns a promise resolving when the transaction is in a block, or rejecting
     * for an error
     */
    setAttribute(credential: string, attribute: string, value: Buffer) {
        let cred = this.credentials.find((c) => c.name === credential);
        if (!cred) {
            cred = new Credential({name: credential, attributes: [new Attribute({name: attribute, value})]});
            this.credentials.push(cred);
        } else {
            const idx = cred.attributes.findIndex((a) => a.name === attribute);
            const attr = new Attribute({name: attribute, value});
            if (idx === -1) {
                cred.attributes.push(attr);
            } else {
                cred.attributes[idx] = attr;
            }
        }
    }

    /**
     * Copy returns a new CredentialStruct with copies of all internal data.
     */
    copy(): CredentialStruct {
        return CredentialStruct.decode(this.toBytes());
    }

    /**
     * Helper to encode the struct using protobuf
     * @returns encoded struct as a buffer
     */
    toBytes(): Buffer {
        return Buffer.from(CredentialStruct.encode(this).finish());
    }
}

/**
 * A credential has a given name used as a key and one or more attributes
 */
export class Credential extends Message<Credential> {

    /**
     * @see README#Message classes
     */
    static register() {
        registerMessage("personhood.Credential", Credential, Attribute);
    }

    static fromNameAttr(name: string, key: string, value: Buffer): Credential {
        return new Credential({name, attributes: [new Attribute({name: key, value})]});
    }

    readonly name: string;
    readonly attributes: Attribute[];

    constructor(props?: Properties<Credential>) {
        super(props);

        this.attributes = this.attributes.slice() || [];
    }
}

/**
 * Attribute of a credential
 */
export class Attribute extends Message<Attribute> {

    /**
     * @see README#Message classes
     */
    static register() {
        registerMessage("personhood.Attribute", Attribute);
    }

    readonly name: string;
    readonly value: Buffer;

    constructor(props?: Properties<Attribute>) {
        super(props);

        this.value = Buffer.from(this.value || EMPTY_BUFFER);
    }
}

export class RecoverySignature {
    static readonly sig = 64;
    static readonly pub = 32;
    static readonly credIID = 32;
    static readonly version = 8;
    static readonly pubSig = RecoverySignature.pub + RecoverySignature.sig;
    static readonly msgBuf = RecoverySignature.credIID + RecoverySignature.pub + RecoverySignature.version;

    constructor(public credentialIID: InstanceID, public signature: Buffer) {
    }
}

CredentialStruct.register();
Credential.register();
Attribute.register();

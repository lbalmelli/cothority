import Long from "long";
import ByzCoinRPC from "../../src/byzcoin/byzcoin-rpc";
import CoinInstance from "../../src/byzcoin/contracts/coin-instance";
import { SPAWNER_COIN } from "../../src/byzcoin/contracts/spawner-instance";
import Rules from "../../src/darc/rules";
import { BLOCK_INTERVAL, ROSTER, SIGNER, startConodes } from "../support/conondes";

describe("CoinInstance Tests", () => {
    const roster = ROSTER.slice(0, 4);

    beforeAll(async () => {
        await startConodes();
    });

    it("should spawn a coin instance", async () => {
        const darc = ByzCoinRPC.makeGenesisDarc([SIGNER], roster);
        darc.addIdentity("spawn:coin", SIGNER, Rules.OR);
        darc.addIdentity("invoke:coin.mint", SIGNER, Rules.OR);
        darc.addIdentity("invoke:coin.transfer", SIGNER, Rules.OR);

        const rpc = await ByzCoinRPC.newByzCoinRPC(roster, darc, BLOCK_INTERVAL);
        const ci = await CoinInstance.spawn(rpc, darc.getBaseID(), [SIGNER], SPAWNER_COIN);

        expect(ci.coin.value.toNumber()).toBe(0);

        await ci.mint([SIGNER], Long.fromNumber(1000));
        await ci.update();

        expect(ci.coin.value.toNumber()).toBe(1000);

        const ci2 = await CoinInstance.spawn(rpc, darc.getBaseID(), [SIGNER], SPAWNER_COIN);
        await ci.transfer(Long.fromNumber(50), ci2.id, [SIGNER]);

        await ci.update();
        await ci2.update();

        expect(ci.coin.value.toNumber()).toBe(950);
        expect(ci2.coin.value.toNumber()).toBe(50);
    });
});

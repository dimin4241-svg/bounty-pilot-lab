// Source-only local Hardhat differential, appended to Boson's own test fixture.
// Does not call Polygon or any external protocol endpoint.
const fs = require("fs");
const path = process.argv[2];
const src = fs.readFileSync(path, "utf8");
const marker = "\n});\n";
const end = src.lastIndexOf(marker);
if (end < 0) throw Error("Boson fixture structure changed; refuse injection.");
const insertion = `
  it("Bounty Pilot native differential: atomic versus legacy fund conservation", async function () {
    const id = "1";
    const before = await ethers.provider.getBalance(protocolDiamondAddress);
    const buyerAddress = await buyer.getAddress();

    // Negative control: insufficient payment must not change protocol funds.
    await expect(
      orchestrationHandler.connect(buyer).commitToOfferAndRedeemVoucher(id, { value: BigInt(offer.price) - 1n })
    ).to.be.revertedWithCustomError(bosonErrors, RevertReasons.INSUFFICIENT_VALUE_RECEIVED);
    assert.equal((await ethers.provider.getBalance(protocolDiamondAddress)).toString(), before.toString());

    const snapshot = await getSnapshot();
    const read = async () => {
      const [exists, state] = await exchangeHandler.getExchangeState(id);
      const [, currentOffer] = await offerHandler.getOffer(id);
      const funds = await fundsHandler.getAvailableFunds(seller.id, [ZeroAddress]);
      const currentBalance = await ethers.provider.getBalance(protocolDiamondAddress);
      return {
        exists,
        state: state.toString(),
        balanceDelta: (currentBalance - before).toString(),
        quantityRemaining: currentOffer.quantityAvailable.toString(),
        sellerAvailable: funds[0].availableAmount.toString()
      };
    };

    await (await orchestrationHandler.connect(buyer).commitToOfferAndRedeemVoucher(id, { value: offer.price })).wait();
    const atomic = await read();

    await revertToSnapshot(snapshot);

    await (await exchangeCommitHandler.connect(buyer).commitToOffer(buyerAddress, id, { value: offer.price })).wait();
    await (await exchangeHandler.connect(buyer).redeemVoucher(id)).wait();
    const legacy = await read();

    assert.deepEqual(atomic, legacy, "Atomic and legacy routes must conserve funds and state equally");
    assert.equal(atomic.balanceDelta, BigInt(offer.price).toString(), "Exact buyer price received once");
    assert.equal(atomic.state, ExchangeState.Redeemed.toString());
    console.log("BPLAB-DIFF: " + JSON.stringify({ atomic, legacy, negativeControl: "reverted/no-balance-change" }));
  });
`;
fs.writeFileSync(path, src.slice(0,end)+insertion+src.slice(end));

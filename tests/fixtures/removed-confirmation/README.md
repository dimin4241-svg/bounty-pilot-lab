# Fixtures: a redesign that deleted a confirmation

`6dc393af6-stellar-redesign.diff` is the real diff of trezor-firmware `6dc393af6`,
"refactor(core): improve Stellar signing UX" (20 August 2025), restricted to
`core/src/apps/stellar` and `core/translations/en.json` - the two sides of the signal: the code
that stopped referencing a label, and the catalogue that stopped carrying its string.

Eight labels left both at once, and **four of the eight were the network display**:
`stellar__confirm_network`, `stellar__on_network_template`, `stellar__private_network`,
`stellar__testnet_network`.

Thirteen months later `7e4bbee93` put it back. Its message is in
`7e4bbee93-restores-it-message.txt`, and it is the whole case for this generator in Trezor's own
words:

> The network was intentionally omitted from the confirmation flow during a recent redesign ...
> However, the stated rationale somewhat overlooked users that wish to interact with multiple
> networks. For users that have accounts both on mainnet and testnet, it is crucial to be able to
> distinguish that they don't sign a transaction for mainnet that was actually meant to be sent to
> testnet only.

Nothing was broken by the redesign. Something was just no longer shown, and it took a year and a
report to notice.

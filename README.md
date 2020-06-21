**NOTICE Mar 1 2018:** The atomic swap contract has been updated to specify the
secret sizes to prevent fraudulent swaps between two cryptocurrencies with
different maximum data sizes.  Old contracts will not be usable by the new tools
and vice-versa.  Please rebuild all tools before conducting new atomic swaps.

# Decred-compatible cross-chain atomic swapping

This repository contains utilities to manually perform cross-chain atomic swaps
between various supported pairs of cryptocurrencies.  At the moment, support
exists for the following coins and wallets:

* Bitcoin ([Bitcoin Core](https://github.com/bitcoin/bitcoin))
* Bitcoin Cash ([Bitcoin ABC](https://github.com/Bitcoin-ABC/bitcoin-abc), [Bitcoin Unlimited](https://github.com/BitcoinUnlimited/BitcoinUnlimited), [Bitcoin XT](https://github.com/bitcoinxt/bitcoinxt))
* Decred ([dcrwallet](https://github.com/decred/dcrwallet))
* Litecoin ([Litecoin Core](https://github.com/litecoin-project/litecoin))
* Megacoin ([Megacoin Core](https://github.com/LIMXTEC/Megacoin))
* Monacoin ([Monacoin Core](https://github.com/monacoinproject/monacoin))
* Particl ([Particl Core](https://github.com/particl/particl-core))
* Qtum ([Qtum Core](https://github.com/qtumproject/qtum))
* Vertcoin ([Vertcoin Core](https://github.com/vertcoin/vertcoin))
* Viacoin ([Viacoin Core](https://github.com/viacoin/viacoin))
* Zcoin ([Zcoin Core](https://github.com/zcoinofficial/zcoin))

External support exists for the following coins and wallets:

* ThreeFold Token ([ThreeFold Chain](https://github.com/threefoldfoundation/tfchain))

Pull requests implementing support for additional cryptocurrencies and wallets
are encouraged.  See [GitHub project
1](https://github.com/decred/atomicswap/projects/1) for the status of coins
being considered.  Implementing support for a new cryptocurrency provides atomic
swap compatibility between all current and future supported coins.

These tools do not operate solely on-chain.  A side-channel is required between
each party performing the swap in order to exchange additional data.  This
side-channel could be as simple as a text chat and copying data.  Until a more
streamlined implementation of the side channel exists, such as the Lightning
Network, these tools suffice as a proof-of-concept for cross-chain atomic swaps
and a way for early adopters to try out the technology.

Due to the requirements of manually exchanging data and creating, sending, and
watching for the relevant transactions, it is highly recommended to read this
README in its entirety before attempting to use these tools.  The sections
below explain the principles on which the tools operate, the instructions for
how to use them safely, and an example swap between Decred and Bitcoin.

## Build instructions

Requires [Go 1.11](https://golang.org/dl/) or later

- Clone atomicswap somewhere outside `$GOPATH`:
  ```
  $ git clone https://github.com/decred/atomicswap && cd atomicswap
  ```

- To install a single tool:
  ```
  $ cd cmd/mecatomicswap && go install
  ```

## Theory

A cross-chain swap is a trade between two users of different cryptocurrencies.
For example, one party may send Decred to a second party's Decred address, while
the second party would send Bitcoin to the first party's Bitcoin address.
However, as the blockchains are unrelated and transactions can not be reversed,
this provides no protection against one of the parties never honoring their end
of the trade.  One common solution to this problem is to introduce a
mutually-trusted third party for escrow.  An atomic cross-chain swap solves this
problem without the need for a third party.

Atomic swaps involve each party paying into a contract transaction, one contract
for each blockchain.  The contracts contain an output that is spendable by
either party, but the rules required for redemption are different for each party
involved.

One party (called counterparty 1 or the initiator) generates a secret and pays
the intended trade amount into a contract transaction.  The contract output can
be redeemed by the second party (called counterparty 2 or the participant) as
long as the secret is known.  If a period of time (typically 48 hours) expires
after the contract transaction has been mined but has not been redeemed by the
participant, the contract output can be refunded back to the initiator's wallet.

For simplicity, we assume the initiator wishes to trade Bitcoin for Decred with
the participant.  The initiator can also trade Decred for Bitcoin and the steps
will be the same, but with each step performed on the other blockchain.

The participant is unable to spend from the initiator's Bitcoin contract at this
point because the secret is unknown by them.  If the initiator revealed their
secret at this point, the participant could spend from the contract without ever
honoring their end of the trade.

The participant creates a similar contract transaction to the initiator's but on
the Decred blockchain and pays the intended Decred amount into the contract.
However, for the initiator to redeem the output, their own secret must be
revealed.  For the participant to create their contract, the initiator must
reveal not the secret, but a cryptographic hash of the secret to the
participant.  The participant's contract can also be refunded by the
participant, but only after half the period of time that the initiator is
required to wait before their contract can be refunded (typically 24 hours).

With each side paying into a contract on each blockchain, and each party unable
to perform their refund until the allotted time expires, the initiator redeems
the participant's Decred contract, thereby revealing the secret to the
participant.  The secret is then extracted from the initiator's redeeming Decred
transaction providing the participant with the ability to redeem the initiator's
Bitcoin contract.

This procedure is atomic (with timeout) as it gives each party at least 24 hours
to redeem their coins on the other blockchain before a refund can be performed.

The image below provides a visual of the steps each party performs and the
transfer of data between each party.

<img src="workflow.svg" width="100%" height=650 />

## Command line

Separate command line utilities are provided to handle the transactions required
to perform a cross-chain atomic swap for each supported blockchain.  For a swap
between Bitcoin and Decred, the two utilities `btcatomicswap` and
`mecatomicswap` are used.  Both tools must be used by both parties performing
the swap.

Different tools may require different flags to use them with the supported
wallet.  For example, `btcatomicswap` includes flags for the RPC username and
password while `mecatomicswap` does not.  Running a tool without any parameters
will show the full usage help.

All of the tools support the same six commands.  These commands are:

```
Commands:
  initiate <participant address> <amount>
  participate <initiator address> <amount> <secret hash>
  redeem <contract> <contract transaction> <secret>
  refund <contract> <contract transaction>
  extractsecret <redemption transaction> <secret hash>
  auditcontract <contract> <contract transaction>
```

**`initiate <participant address> <amount>`**

The `initiate` command is performed by the initiator to create the first
contract.  The contract is created with a locktime of 48 hours in the future.
This command returns the secret, the secret hash, the contract script, the
contract transaction, and a refund transaction that can be sent after 48 hours
if necessary.

Running this command will prompt for whether to publish the contract
transaction.  If everything looks correct, the transaction should be published.
The refund transaction should be saved in case a refund is required to be made
later.

For mecatomicswap, this step prompts for the wallet passphrase.  For the
btcatomicswap and ltcatomicswap tools the wallet must already be unlocked.

**`participate <initiator address> <amount> <secret hash>`**

The `participate` command is performed by the participant to create a contract
on the second blockchain.  It operates similarly to `initiate` but requires
using the secret hash from the initiator's contract and creates the contract
with a locktime of 24 hours.

Running this command will prompt for whether to publish the contract
transaction.  If everything looks correct, the transaction should be published.
The refund transaction should be saved in case a refund is required to be made
later.

For mecatomicswap, this step prompts for the wallet passphrase.  For the
btcatomicswap and ltcatomicswap tools the wallet must already be unlocked.

**`redeem <contract> <contract transaction> <secret>`**

The `redeem` command is performed by both parties to redeem coins paid into the
contract created by the other party.  Redeeming requires the secret and must be
performed by the initiator first.  Once the initiator's redemption has been
published, the secret may be extracted from the transaction and the participant
may also redeem their coins.

Running this command will prompt for whether to publish the redemption
transaction. If everything looks correct, the transaction should be published.

For mecatomicswap, this step prompts for the wallet passphrase.  For the
btcatomicswap and ltcatomicswap tools the wallet must already be unlocked.

**`refund <contract> <contract transaction>`**

The `refund` command is used to create and send a refund of a contract
transaction.  While the refund transaction is created and displayed during
contract creation in the initiate and participate steps, the refund can also be
created after the fact in case there was any issue sending the transaction (e.g.
the contract transaction was malleated or the refund fee is now too low).

Running this command will prompt for whether to publish the redemption
transaction. If everything looks correct, the transaction should be published.

**`extractsecret <redemption transaction> <secret hash>`**

The `extractsecret` command is used by the participant to extract the secret
from the initiator's redemption transaction.  With the secret known, the
participant may claim the coins paid into the initiator's contract.

The secret hash is a required parameter so that "nonstandard" redemption
transactions won't confuse the tool and the secret can still be discovered.

**`auditcontract <contract> <contract transaction>`**

The `auditcontract` command inspects a contract script and parses out the
addresses that may claim the output, the locktime, and the secret hash.  It also
validates that the contract transaction pays to the contract and reports the
contract output amount.  Each party should audit the contract provided by the
other to verify that their address is the recipient address, the output value is
correct, and that the locktime is sensible.

## Example

The first step is for both parties to exchange addresses on both blockchains. If
party A (the initiator) wishes to trade Bitcoin for Decred, party B (the
participant) must provide their Bitcoin address and the initiator must provide
the participant their Decred address.

_Party A runs:_
```
$ megacoin-cli getnewaddress "" "legacy"
MBetAaqPXDnP4aGvdsMdBtTGbR3Ys265nm
```

_Party B runs:_
```
$ bitcoin-cli -testnet getnewaddress "" "legacy"
msbQd8kcm4Dc9yxH4JyaVZXQwESz7uWJPs
```

*Note:* It is normal for neither of these addresses to show any activity on
block explorers.  They are only used in nonstandard scripts that the block
explorers do not recognize.

A initiates the process by using `btcatomicswap` to pay 0.01 BTC (+ redeem fee) into the Bitcoin
contract using B's Bitcoin address, sending the contract transaction, and
sharing the secret hash (*not* the secret), contract, and contract transaction
with B.  The refund transaction can not be sent until the locktime expires, but
should be saved in case a refund is necessary.

_Party A runs:_
```
$ btcatomicswap --testnet --rpcuser=user --rpcpass=pass initiate msbQd8kcm4Dc9yxH4JyaVZXQwESz7uWJPs 1.0
Secret:      b05cdb7c4e9e581f0d79d014cc6c342e926a18af89ca624d1f0ba15fece83abd
Secret hash: 9d1e0c9340b98f99241313bb6b984ca83bb7d90c46bab0aceadffc86c66a76ec

Contract fee: 0.00000221 BTC (0.00001000 BTC/kB)
Refund fee:   0.00000297 BTC (0.00001017 BTC/kB)
Possible redeem fee: 0.0000033 BTC (0.00001015 BTC/kB)

Contract (2Mz4Njb7W4qFe9xtyyP4BHsVVKN25cKQghr):
6382012088a8209d1e0c9340b98f99241313bb6b984ca83bb7d90c46bab0aceadffc86c66a76ec8876a914847926cd75ca892cc983746b7605d9c995cceb9a670448cdf15eb17576a9146fce0c4328d732d59e2a9a6699a7d62bc2332e726888ac

Contract transaction (c7bfae67201fd9c092d0caab5f666d1e751db4131dfd223e63d98322885d27c9):
0200000001aec4e81b0715d974c69364e962bfc5bc1f92f23b0d519fdabf1a5bb9faae4eb6000000006a47304402204cf1dd0af6048260d8a7d16b4da261dcc2924d700b538452e91427c3807084120220620c85c2caa5b7bf6f4ad187f22404c00fcf04d618e05ce5a6c35f2660323d64012102055da5628933fd5bbdd35fb91eb1ea2d04b4104a1d4b1856075be5a2c848bb9fffffffff0284d801000000000017a914057d92ef488b26d62246b85f7a68ad86f02b32fe878a430f000000000017a9144abb9b320d13ea7ef5a970e37f7394a6aa1dc6308700000000

Refund transaction (31e6bbb38bedd0a7a9acf360264b84cc5c5a0b4bb2cfe37ba079933743be1768):
0200000001c9275d882283d9633e22fd1d13b41d751e6d665fabcad092c0d91f2067aebfc701000000cf483045022100bea066bc8556568f4e4c6842a3a3d7fdad9841f6f9445e16da01bbe77361b9130220014a39bd0a21ab663a7a9b3476f86e180faa275c62b470cf830d28439ee8c83e012102c503b466411d20c3de286bba52f93e033a66c7736ca62ddd2be9dddd7481b62f004c616382012088a8209d1e0c9340b98f99241313bb6b984ca83bb7d90c46bab0aceadffc86c66a76ec8876a914847926cd75ca892cc983746b7605d9c995cceb9a670448cdf15eb17576a9146fce0c4328d732d59e2a9a6699a7d62bc2332e726888ac000000000161420f00000000001976a91408f79ca4ccf8f12a0f6874b5a043e11ee25c333488ac48cdf15e

Publish contract transaction? [y/N] y
Published contract transaction (6382012088a8209d1e0c9340b98f99241313bb6b984ca83bb7d90c46bab0aceadffc86c66a76ec8876a914847926cd75ca892cc983746b7605d9c995cceb9a670448cdf15eb17576a9146fce0c4328d732d59e2a9a6699a7d62bc2332e726888ac)
```

Once A has initialized the swap, B must audit the contract and contract
transaction to verify:

1. The recipient address was the BTC address that was provided to A
2. The contract value is the expected amount of BTC to receive
3. The locktime was set to 48 hours in the future

_Party B runs:_
```
$ btcatomicswap --testnet auditcontract 6382012088a8209d1e0c9340b98f99241313bb6b984ca83bb7d90c46bab0aceadffc86c66a76ec8876a914847926cd75ca892cc983746b7605d9c995cceb9a670448cdf15eb17576a9146fce0c4328d732d59e2a9a6699a7d62bc2332e726888ac 0200000001aec4e81b0715d974c69364e962bfc5bc1f92f23b0d519fdabf1a5bb9faae4eb6000000006a47304402204cf1dd0af6048260d8a7d16b4da261dcc2924d700b538452e91427c3807084120220620c85c2caa5b7bf6f4ad187f22404c00fcf04d618e05ce5a6c35f2660323d64012102055da5628933fd5bbdd35fb91eb1ea2d04b4104a1d4b1856075be5a2c848bb9fffffffff0284d801000000000017a914057d92ef488b26d62246b85f7a68ad86f02b32fe878a430f000000000017a9144abb9b320d13ea7ef5a970e37f7394a6aa1dc6308700000000
Contract address:        2Mz4Njb7W4qFe9xtyyP4BHsVVKN25cKQghr
Contract value:          0.0100033 BTC
Recipient address:       msbQd8kcm4Dc9yxH4JyaVZXQwESz7uWJPs
Author's refund address: mqi88oiWKMQ9CReRj2nJzyq71sPehdQfdV

Secret hash: 9d1e0c9340b98f99241313bb6b984ca83bb7d90c46bab0aceadffc86c66a76ec

Locktime: 2020-06-23 09:37:12 +0000 UTC
Locktime reached in 47h55m52s
```

Auditing the contract also reveals the hash of the secret, which is needed for
the next step.

Once B trusts the contract, they may participate in the cross-chain atomic swap
by paying the intended Megacoin amount (5.0 in this example) into a Megacoin
contract using the same secret hash.  The contract transaction may be published
at this point.  The refund transaction can not be sent until the locktime
expires, but should be saved in case a refund is necessary.

_Party B runs:_
```
$ mecatomicswap --testnet participate MBetAaqPXDnP4aGvdsMdBtTGbR3Ys265nm 5.0000033 9d1e0c9340b98f99241313bb6b984ca83bb7d90c46bab0aceadffc86c66a76ec

Contract fee: 0.00000223 MEC (0.00001000 MEC/kB)
Refund fee:   0.00000297 MEC (0.00001021 MEC/kB)
Possible redeem fee: 0.00000330 MEC (0.00001015 MEC/kB)

Contract (3FzdtpxFv7PhFyXmTu5HSZZCrKmF6XLxKb):
6382012088a8209d1e0c9340b98f99241313bb6b984ca83bb7d90c46bab0aceadffc86c66a76ec8876a914292d44a80d51a97d802ab22e3abc87b4d3e50a6367040c7df05eb17576a9148efe29d748b4203a549b19c45579a5e0ceaec5c96888ac

Contract transaction (42ee5fcc334abccbc42a3b1659d08ffbb297822f47d9d90369a2c19b4c05ab40):
020000000193fd66a2ecd69cd83b15f10bd76ca908fa5d825e50e8b566b1407b4944c5f3a2000000006a47304402205e0689a0bfd9ffab8646d0ef9e8130c73d7f803b18d0266c54e211f199f0eb92022029c9f41784ac72b51e887865f65844294e9920d48612abe33142cf43770f0a05012103627b409e9f9c82dd3f6e713c09cacada2bf13ab6fb67d9f4cd2b2052029d1621ffffffff024a66cd1d0000000017a9149ce6dbe18a3d0f95d51ce33af09b940de818d0718725a9b903000000001976a914ebb43b8282744f4c5fffd3a045ff54f43137866b88ac00000000

Refund transaction (5e4f1fd24eef9793d394dad4aacca06312d41d4117b4f2cedf44ed75ba703c61):
020000000140ab054c9bc1a26903d9d9472f8297b2fb8fd059163b2ac4cbbc4a33cc5fee4200000000ce47304402203196e5a47598fd77d814a55c0caa745e2af653c2ac730e75bb89d86466ac7f2a02201958cb540e27c5c52b586b7d8d5aa23a6b7bdc30aebf2ac667c6eb47c0774f1f0121028835e08865f59d0e9e7ad3f0b752e7a5736f978b4203b35bdc20556120a9cc45004c616382012088a8209d1e0c9340b98f99241313bb6b984ca83bb7d90c46bab0aceadffc86c66a76ec8876a914292d44a80d51a97d802ab22e3abc87b4d3e50a6367040c7df05eb17576a9148efe29d748b4203a549b19c45579a5e0ceaec5c96888ac00000000012165cd1d000000001976a9140b836a9da9572a29280b82096e713641e4e7fe7e88ac0c7df05e

Publish contract transaction? [y/N] y
Published contract transaction (42ee5fcc334abccbc42a3b1659d08ffbb297822f47d9d90369a2c19b4c05ab40)
```

B now informs A that the Megacoin contract transaction has been created and
published, and provides the contract details to A.

Just as B needed to audit A's contract before locking their coins in a contract,
A must do the same with B's contract before withdrawing from the contract.  A
audits the contract and contract transaction to verify:

1. The recipient address was the MEC address that was provided to B
2. The contract value is the expected amount of MEC to receive
3. The locktime was set to 24 hours in the future
4. The secret hash matches the value previously known

_Party A runs:_
```
$ mecatomicswap --testnet auditcontract 6382012088a8209d1e0c9340b98f99241313bb6b984ca83bb7d90c46bab0aceadffc86c66a76ec8876a914292d44a80d51a97d802ab22e3abc87b4d3e50a6367040c7df05eb17576a9148efe29d748b4203a549b19c45579a5e0ceaec5c96888ac 020000000193fd66a2ecd69cd83b15f10bd76ca908fa5d825e50e8b566b1407b4944c5f3a2000000006a47304402205e0689a0bfd9ffab8646d0ef9e8130c73d7f803b18d0266c54e211f199f0eb92022029c9f41784ac72b51e887865f65844294e9920d48612abe33142cf43770f0a05012103627b409e9f9c82dd3f6e713c09cacada2bf13ab6fb67d9f4cd2b2052029d1621ffffffff024a66cd1d0000000017a9149ce6dbe18a3d0f95d51ce33af09b940de818d0718725a9b903000000001976a914ebb43b8282744f4c5fffd3a045ff54f43137866b88ac00000000
Contract address:        3FzdtpxFv7PhFyXmTu5HSZZCrKmF6XLxKb
Contract value:          5.0000033 MEC
Recipient address:       MBetAaqPXDnP4aGvdsMdBtTGbR3Ys265nm
Author's refund address: MLwEfFn5ioxmP2ggpJsfEQs65buXqf2g3Z

Secret hash: 9d1e0c9340b98f99241313bb6b984ca83bb7d90c46bab0aceadffc86c66a76ec

Locktime: 2020-06-22 09:42:36 +0000 UTC
Locktime reached in 23h57m58s
```

Now that both parties have paid into their respective contracts, A may withdraw
from the Megacoin contract.  This step involves publishing a transaction which
reveals the secret to B, allowing B to withdraw from the Bitcoin contract.

_Party A runs:_
```
$ mecatomicswap --testnet redeem 6382012088a8209d1e0c9340b98f99241313bb6b984ca83bb7d90c46bab0aceadffc86c66a76ec8876a914292d44a80d51a97d802ab22e3abc87b4d3e50a6367040c7df05eb17576a9148efe29d748b4203a549b19c45579a5e0ceaec5c96888ac 020000000193fd66a2ecd69cd83b15f10bd76ca908fa5d825e50e8b566b1407b4944c5f3a2000000006a47304402205e0689a0bfd9ffab8646d0ef9e8130c73d7f803b18d0266c54e211f199f0eb92022029c9f41784ac72b51e887865f65844294e9920d48612abe33142cf43770f0a05012103627b409e9f9c82dd3f6e713c09cacada2bf13ab6fb67d9f4cd2b2052029d1621ffffffff024a66cd1d0000000017a9149ce6dbe18a3d0f95d51ce33af09b940de818d0718725a9b903000000001976a914ebb43b8282744f4c5fffd3a045ff54f43137866b88ac00000000 b05cdb7c4e9e581f0d79d014cc6c342e926a18af89ca624d1f0ba15fece83abd

Redeem fee: 0.00000330 MEC (0.00001019 MEC/kB)

Redeem transaction (87214203863569ce7421aee3f90a7d1a29a89abc41e9c267f0ec35cb37ac18ae):
020000000140ab054c9bc1a26903d9d9472f8297b2fb8fd059163b2ac4cbbc4a33cc5fee4200000000ef47304402203818e91072cee4aefecd4e2af0fa4c25e6bc216164b577ce4e2dbed47a301b8a022072cc391ad715469a609568be556765038cd9bc64ec2122680af1ac3c44b236ce0121032df824fdddebbd405da72ea1775230224e34bb6a991f86903276d8bff2110a4a20b05cdb7c4e9e581f0d79d014cc6c342e926a18af89ca624d1f0ba15fece83abd514c616382012088a8209d1e0c9340b98f99241313bb6b984ca83bb7d90c46bab0aceadffc86c66a76ec8876a914292d44a80d51a97d802ab22e3abc87b4d3e50a6367040c7df05eb17576a9148efe29d748b4203a549b19c45579a5e0ceaec5c96888acffffffff010065cd1d000000001976a9146f11ea79669a53434722c810253cc3f98be3257688ac0c7df05e

Publish redeem transaction? [y/N] y
Published redeem transaction (87214203863569ce7421aee3f90a7d1a29a89abc41e9c267f0ec35cb37ac18ae)
```

Now that A has withdrawn from the Megacoin contract and revealed the secret, B
must extract the secret from this redemption transaction.  B may watch a block
explorer to see when the Megacoin contract output was spent and look up the
redeeming transaction.

_Party B runs:_
```
$ mecatomicswap --testnet extractsecret 020000000140ab054c9bc1a26903d9d9472f8297b2fb8fd059163b2ac4cbbc4a33cc5fee4200000000ef47304402203818e91072cee4aefecd4e2af0fa4c25e6bc216164b577ce4e2dbed47a301b8a022072cc391ad715469a609568be556765038cd9bc64ec2122680af1ac3c44b236ce0121032df824fdddebbd405da72ea1775230224e34bb6a991f86903276d8bff2110a4a20b05cdb7c4e9e581f0d79d014cc6c342e926a18af89ca624d1f0ba15fece83abd514c616382012088a8209d1e0c9340b98f99241313bb6b984ca83bb7d90c46bab0aceadffc86c66a76ec8876a914292d44a80d51a97d802ab22e3abc87b4d3e50a6367040c7df05eb17576a9148efe29d748b4203a549b19c45579a5e0ceaec5c96888acffffffff010065cd1d000000001976a9146f11ea79669a53434722c810253cc3f98be3257688ac0c7df05e 9d1e0c9340b98f99241313bb6b984ca83bb7d90c46bab0aceadffc86c66a76ec
Secret: b05cdb7c4e9e581f0d79d014cc6c342e926a18af89ca624d1f0ba15fece83abd
```

With the secret known, B may redeem from A's Bitcoin contract.

_Party B runs:_
```
$ btcatomicswap --testnet --rpcuser=user --rpcpass=pass redeem 6382012088a8209d1e0c9340b98f99241313bb6b984ca83bb7d90c46bab0aceadffc86c66a76ec8876a914847926cd75ca892cc983746b7605d9c995cceb9a670448cdf15eb17576a9146fce0c4328d732d59e2a9a6699a7d62bc2332e726888ac 0200000001aec4e81b0715d974c69364e962bfc5bc1f92f23b0d519fdabf1a5bb9faae4eb6000000006a47304402204cf1dd0af6048260d8a7d16b4da261dcc2924d700b538452e91427c3807084120220620c85c2caa5b7bf6f4ad187f22404c00fcf04d618e05ce5a6c35f2660323d64012102055da5628933fd5bbdd35fb91eb1ea2d04b4104a1d4b1856075be5a2c848bb9fffffffff0284d801000000000017a914057d92ef488b26d62246b85f7a68ad86f02b32fe878a430f000000000017a9144abb9b320d13ea7ef5a970e37f7394a6aa1dc6308700000000 b05cdb7c4e9e581f0d79d014cc6c342e926a18af89ca624d1f0ba15fece83abd
Redeem fee: 0.0000033 BTC (0.00001015 BTC/kB)

Redeem transaction (94e100bb7decf786c69181e10e76aa5223af554bef19f702b2516b46b15e746d):
0200000001c9275d882283d9633e22fd1d13b41d751e6d665fabcad092c0d91f2067aebfc701000000f0483045022100f0dc85797defc3da08500603521db6d91457e4a4c645e55318966a5ae2e0619e02201ff4fb50025f06b9c838e3397cdec662fd6be909ed6125a3db5dc5f154fd33ef0121032a5d5d785e7d583fdc6af53d3360d8cda0bba9b3f537504b4f8aa324dda290ec20b05cdb7c4e9e581f0d79d014cc6c342e926a18af89ca624d1f0ba15fece83abd514c616382012088a8209d1e0c9340b98f99241313bb6b984ca83bb7d90c46bab0aceadffc86c66a76ec8876a914847926cd75ca892cc983746b7605d9c995cceb9a670448cdf15eb17576a9146fce0c4328d732d59e2a9a6699a7d62bc2332e726888acffffffff0140420f00000000001976a9148add8f3c255f5f1b2b1d61f2df7a7f2958132fb488ac48cdf15e

Publish redeem transaction? [y/N] y
Published redeem transaction (94e100bb7decf786c69181e10e76aa5223af554bef19f702b2516b46b15e746d)
```

The cross-chain atomic swap is now completed and successful.  This example was
performed on the public Bitcoin testnet and Megacoin blockchains.  For reference,
here are the four transactions involved:

| Description | Transaction |
| - | - |
| Bitcoin contract created by A | [c7bfae67201fd9c092d0caab5f666d1e751db4131dfd223e63d98322885d27c9](https://blockstream.info/testnet/tx/c7bfae67201fd9c092d0caab5f666d1e751db4131dfd223e63d98322885d27c9) |
| Megacoin contract created by B | [42ee5fcc334abccbc42a3b1659d08ffbb297822f47d9d90369a2c19b4c05ab40](https://chainz.cryptoid.info/mec/tx.dws?42ee5fcc334abccbc42a3b1659d08ffbb297822f47d9d90369a2c19b4c05ab40.htm) |
| A's Megacoin redemption | [87214203863569ce7421aee3f90a7d1a29a89abc41e9c267f0ec35cb37ac18ae](https://chainz.cryptoid.info/mec/tx.dws?87214203863569ce7421aee3f90a7d1a29a89abc41e9c267f0ec35cb37ac18ae.htm) |
| B's Bitcoin redemption | [94e100bb7decf786c69181e10e76aa5223af554bef19f702b2516b46b15e746d](https://blockstream.info/testnet/tx/94e100bb7decf786c69181e10e76aa5223af554bef19f702b2516b46b15e746d) |

If at any point either party attempts to fraud (e.g. creating an invalid
contract, not revealing the secret and refunding, etc.) both parties have the
ability to issue the refund transaction created in the initiate/participate step
and refund the contract.

## Discovering raw transactions

Several steps require working with a raw transaction published by the other
party.  While the transactions can sometimes be looked up from a local node
using the `getrawtransaction` JSON-RPC, this method can be unreliable since the
set of queryable transactions depends on the current UTXO set or may require a
transaction index to be enabled.

Another method of discovering these transactions is to use a public blockchain
explorer.  Not all explorers expose this info through the main user interface so
the API endpoints may need to be used instead.

For Insight-based block explorers, such as the Bitcoin block explorer on
[test-]insight.bitpay.com, the Litecoin block explorer on
{insight,testnet}.litecore.io, the API endpoint `/api/rawtx/<txhash>` can be used
to return a JSON object containing the raw transaction.
For cryptoID explorers, the API endpoint `/explorer/tx.raw.dws?coin=<coin>&id=<txhash>` can be used
to return a JSON object containing the raw transaction.

## License

These tools are licensed under the [copyfree](http://copyfree.org) ISC License.

<!-- Auto-generated from Gray Paper v0.7.2 LaTeX source -->
<!-- Source: https://github.com/gavofyork/graypaper (tag v0.7.2) -->
<!-- Generated with pandoc 3.1.3 -->

# Introduction

## Nomenclature

In this paper, we introduce a decentralized, crypto-economic protocol to which the Polkadot Network will transition itself in a major revision on the basis of approval by its governance apparatus.

An early, unrefined, version of this protocol was first proposed in Polkadot Fellowship RFC, known as *CoreJam*. CoreJam takes its name after the collect/refine/join/accumulate model of computation at the heart of its service proposition. While the CoreJam RFC suggested an incomplete, scope-limited alteration to the Polkadot protocol, refers to a complete and coherent overall blockchain protocol.

## Driving Factors

Within the realm of blockchain and the wider Web3, we are driven by the need first and foremost to deliver resilience. A proper Web3 digital system should honor a declared service profile—and ideally meet even perceived expectations—regardless of the desires, wealth or power of any economic actors including individuals, organizations and, indeed, other Web3 systems. Inevitably this is aspirational, and we must be pragmatic over how perfectly this may really be delivered. Nonetheless, a Web3 system should aim to provide such radically strong guarantees that, for practical purposes, the system may be described as *unstoppable*.

While Bitcoin is, perhaps, the first example of such a system within the economic domain, it was not general purpose in terms of the nature of the service it offered. A rules-based service is only as useful as the generality of the rules which may be conceived and placed within it. Bitcoin’s rules allowed for an initial use-case, namely a fixed-issuance token, ownership of which is well-approximated and autonomously enforced through knowledge of a secret, as well as some further elaborations on this theme.

Later, Ethereum would provide a categorically more general-purpose rule set, one which was practically Turing complete.[^1] In the context of Web3 where we are aiming to deliver a massively multiuser application platform, generality is crucial, and thus we take this as a given.

Beyond resilience and generality, things get more interesting, and we must look a little deeper to understand what our driving factors are. For the present purposes, we identify three additional goals:

1.  Resilience: highly resistant from being stopped, corrupted and censored.

2.  Generality: able to perform Turing-complete computation.

3.  Performance: able to perform computation quickly and at low cost.

4.  Coherency: the causal relationship possible between different elements of state and thus how well individual applications may be composed.

5.  Accessibility: negligible barriers to innovation; easy, fast, cheap and permissionless.

As a declared Web3 technology, we make an implicit assumption of the first two items. Interestingly, items enum:performance and enum:coherency are antagonistic according to an information theoretic principle which we are sure must already exist in some form but are nonetheless unaware of a name for it. For argument’s sake we shall name it *size-coherency antagonism*.

## Scaling under Size-Coherency Antagonism

Size-coherency antagonism is a simple principle implying that as the state-space of information systems grow, then the system necessarily becomes less coherent. It is a direct implication of principle that causality is limited by speed. The maximum speed allowed by physics is $C$ the speed of light in a vacuum, however other information systems may have lower bounds: In biological system this is largely determined by various chemical processes whereas in electronic systems is it determined by the speed of electrons in various substances. Distributed software systems will tend to have much lower bounds still, being dependent on a substrate of software, hardware and packet-switched networks of varying reliability.

The argument goes:

1.  The more state a system utilizes for its data-processing, the greater the amount of space this state must occupy.

2.  The more space used, then the greater the mean and variance of distances between state-components.

3.  As the mean and variance increase, then time for causal resolution (i.e. all correct implications of an event to be felt) becomes divergent across the system, causing incoherence.

Setting the question of overall security aside for a moment, we can manage incoherence by fragmenting the system into causally-independent subsystems, each of which is small enough to be coherent. In a resource-rich environment, a bacterium may split into two rather than growing to double its size. This pattern is rather a crude means of dealing with incoherency under growth: intra-system processing has low size and total coherence, inter-system processing supports higher overall sizes but without coherence. It is the principle behind meta-networks such as Polkadot, Cosmos and the predominant vision of a scaled Ethereum (all to be discussed in depth shortly). Such systems typically rely on asynchronous and simplistic communication with “settlement areas” which provide a small-scoped coherent state-space to manage specific interactions such as a token transfer.

The present work explores a middle-ground in the antagonism, avoiding the persistent fragmentation of state-space of the system as with existing approaches. We do this by introducing a new model of computation which pipelines a highly scalable, *mostly coherent* element to a synchronous, fully coherent element. Asynchrony is not avoided, but we bound it to the length of the pipeline and substitute the crude partitioning we see in scalable systems so far with a form of “cache affinity” as it typically seen in multi-CPU systems with a shared RAM.

Unlike with SNARK-based L2-blockchain techniques for scaling, this model draws upon crypto-economic mechanisms and inherits their low-cost and high-performance profiles and averts a bias toward centralization.

## Document Structure

We begin with a brief overview of present scaling approaches in blockchain technology in section 2. In section 3 we define and clarify the notation from which we will draw for our formalisms.

We follow with a broad overview of the protocol in section 4 outlining the major areas including the Polkadot Virtual Machine (PVM), the consensus protocols Safrole and GRANDPA, the common clock and build the foundations of the formalism.

We then continue with the full protocol definition split into two parts: firstly the correct on-chain state-transition formula helpful for all nodes wishing to validate the chain state, and secondly, in sections 14 and 19 the honest strategy for the off-chain actions of any actors who wield a validator key.

The main body ends with a discussion over the performance characteristics of the protocol in section 20 and finally conclude in section 21.

The appendix contains various additional material important for the protocol definition including the PVM in appendices 23 & 24, serialization and Merklization in appendices 25 & 26 and cryptography in appendices 27, 29 & 30. We finish with an index of terms which includes the values of all simple constant terms used in the work in appendix 31, and close with the bibliography.

# Previous Work and Present Trends

In the years since the initial publication of the Ethereum *YP*, the field of blockchain development has grown immensely. Other than scalability, development has been done around underlying consensus algorithms, smart-contract languages and machines and overall state environments. While interesting, these latter subjects are mostly out scope of the present work since they generally do not impact underlying scalability.

## Polkadot

In order to deliver its service, co-opts much of the same game-theoretic and cryptographic machinery as Polkadot known as ELVES and described by . However, major differences exist in the actual service offered with , providing an abstraction much closer to the actual computation model generated by the validator nodes its economy incentivizes.

It was a major point of the original Polkadot proposal, a scalable heterogeneous multichain, to deliver high-performance through partition and distribution of the workload over multiple host machines. In doing so it took an explicit position that composability would be lowered. Polkadot’s constituent components, parachains are, practically speaking, highly isolated in their nature. Though a message passing system (XCMP) exists it is asynchronous, coarse-grained and practically limited by its reliance on a high-level slowly evolving interaction language XCM.

As such, the composability offered by Polkadot between its constituent chains is lower than that of Ethereum-like smart-contract systems offering a single and universal object environment and allowing for the kind of agile and innovative integration which underpins their success. Polkadot, as it stands, is a collection of independent ecosystems with only limited opportunity for collaboration, very similar in ergonomics to bridged blockchains though with a categorically different security profile. A technical proposal known as SPREE would utilize Polkadot’s unique shared-security and improve composability, though blockchains would still remain isolated.

Implementing and launching a blockchain is hard, time-consuming and costly. By its original design, Polkadot limits the clients able to utilize its service to those who are both able to do this and raise a sufficient deposit to win an auction for a long-term slot, one of around 50 at the present time. While not permissioned per se, accessibility is categorically and substantially lower than for smart-contract systems similar to Ethereum.

Enabling as many innovators to participate and interact, both with each other and each other’s user-base, appears to be an important component of success for a Web3 application platform. Accessibility is therefore crucial.

## Ethereum

The Ethereum protocol was formally defined in this paper’s spiritual predecessor, the *Yellow Paper*, by . This was derived in large part from the initial concept paper by . In the decade since the *YP* was published, the *de facto* Ethereum protocol and public network instance have gone through a number of evolutions, primarily structured around introducing flexibility via the transaction format and the instruction set and “precompiles” (niche, sophisticated bonus instructions) of its scripting core, the Ethereum virtual machine (EVM).

Almost one million crypto-economic actors take part in the validation for Ethereum.[^2] Block extension is done through a randomized leader-rotation method where the physical address of the leader is public in advance of their block production.[^3] Ethereum uses Casper-FFG introduced by to determine finality, which with the large validator base finalizes the chain extension around every 13 minutes.

Ethereum’s direct computational performance remains broadly similar to that with which it launched in 2015, with a notable exception that an additional service now allows 1MB of *commitment data* to be hosted per block (all nodes to store it for a limited period). The data cannot be directly utilized by the main state-transition function, but special functions provide proof that the data (or some subsection thereof) is available. According to , the present design direction is to improve on this over the coming years by splitting responsibility for its storage amongst the validator base in a protocol known as *Dank-sharding*.

According to , the scaling strategy of Ethereum would be to couple this data availability with a private market of *roll-ups*, sideband computation facilities of various design, with ZK-SNARK-based roll-ups being a stated preference. Each vendor’s roll-up design, execution and operation comes with its own implications.

One might reasonably assume that a diversified market-based approach for scaling via multivendor roll-ups will allow well-designed solutions to thrive. However, there are potential issues facing the strategy. A research report by on the level of decentralization in the various roll-ups found a broad pattern of centralization, but notes that work is underway to attempt to mitigate this. It remains to be seen how decentralized they can yet be made.

Heterogeneous communication properties (such as datagram latency and semantic range), security properties (such as the costs for reversion, corruption, stalling and censorship) and economic properties (the cost of accepting and processing some incoming message or transaction) may differ, potentially quite dramatically, between major areas of some grand patchwork of roll-ups by various competing vendors. While the overall Ethereum network may eventually provide some or even most of the underlying machinery needed to do the sideband computation it is far from clear that there would be a “grand consolidation” of the various properties should such a thing happen. We have not found any good discussion of the negative ramifications of such a fragmented approach.[^4]

### SNARK Roll-ups

While the protocol’s foundation makes no great presuppositions on the nature of roll-ups, Ethereum’s strategy for sideband computation does centre around SNARK-based rollups and as such the protocol is being evolved into a design that makes sense for this. SNARKs are the product of an area of exotic cryptography which allow proofs to be constructed to demonstrate to a neutral observer that the purported result of performing some predefined computation is correct. The complexity of the verification of these proofs tends to be sub-linear in their size of computation to be proven and will not give away any of the internals of said computation, nor any dependent witness data on which it may rely.

ZK-SNARKs come with constraints. There is a trade-off between the proof’s size, verification complexity and the computational complexity of generating it. Non-trivial computation, and especially the sort of general-purpose computation laden with binary manipulation which makes smart-contracts so appealing, is hard to fit into the model of SNARKs.

To give a practical example, RISC-zero (as assessed by ) is a leading project and provides a platform for producing SNARKs of computation done by a RISC-V virtual machine, an open-source and succinct RISC machine architecture well-supported by tooling. A recent benchmarking report by showed that compared to RISC-zero’s own benchmark, proof generation alone takes over 61,000 times as long as simply recompiling and executing even when executing on 32 times as many cores, using 20,000 times as much RAM and an additional state-of-the-art GPU. According to hardware rental agents <https://cloud-gpus.com/>, the cost multiplier of proving using RISC-zero is 66,000,000x of the cost[^5] to execute using the PolkaVM recompiler.

Many cryptographic primitives become too expensive to be practical to use and specialized algorithms and structures must be substituted. Often times they are otherwise suboptimal. In expectation of the use of SNARKs (such as PLONK as proposed by ), the prevailing design of the Ethereum project’s Dank-sharding availability system uses a form of erasure coding centered around polynomial commitments over a large prime field in order to allow SNARKs to get acceptably performant access to subsections of data. Compared to alternatives, such as a binary field and Merklization in the present work, it leads to a load on the validator nodes orders of magnitude higher in terms of CPU usage.

In addition to their basic cost, SNARKs present no great escape from decentralization and the need for redundancy, leading to further cost multiples. While the need for some benefits of staked decentralization is averted through their verifiable nature, the need to incentivize multiple parties to do much the same work is a requirement to ensure that a single party not form a monopoly (or several not form a cartel). Proving an incorrect state-transition should be impossible, however service integrity may be compromised in other ways; a temporary suspension of proof-generation, even if only for minutes, could amount to major economic ramifications for real-time financial applications.

Real-world examples exist of the pit of centralization giving rise to monopolies. One would be the aforementioned SNARK-based exchange framework; while notionally serving decentralized exchanges, it is in fact centralized with Starkware itself wielding a monopoly over enacting trades through the generation and submission of proofs, leading to a single point of failure—should Starkware’s service become compromised, then the liveness of the system would suffer.

It has yet to be demonstrated that SNARK-based strategies for eliminating the trust from computation will ever be able to compete on a cost-basis with a multi-party crypto-economic platform. All as-yet proposed SNARK-based solutions are heavily reliant on crypto-economic systems to frame them and work around their issues. Data availability and sequencing are two areas well understood as requiring a crypto-economic solution.

We would note that SNARK technology is improving and the cryptographers and engineers behind them do expect improvements in the coming years. In a recent article by we see some credible speculation that with some recent advancements in cryptographic techniques, slowdowns for proof generation could be as little as 50,000x from regular native execution and much of this could be parallelized. This is substantially better than the present situation, but still several orders of magnitude greater than would be required to compete on a cost-basis with established crypto-economic techniques such as ELVES.

## Fragmented Meta-Networks

Directions for general-purpose computation scalability taken by other projects broadly centre around one of two approaches; either what might be termed a *fragmentation* approach or alternatively a *centralization* approach. We argue that neither approach offers a compelling solution.

The fragmentation approach is heralded by projects such as Cosmos (proposed by ) and Avalanche (by ). It involves a system fragmented by networks of a homogenous consensus mechanic, yet staffed by separately motivated sets of validators. This is in contrast to Polkadot’s single validator set and Ethereum’s declared strategy of heterogeneous roll-ups secured partially by the same validator set operating under a coherent incentive framework. The homogeneity of said fragmentation approach allows for reasonably consistent messaging mechanics, helping to present a fairly unified interface to the multitude of connected networks.

However, the apparent consistency is superficial. The networks are trustless only by assuming correct operation of their validators, who operate under a crypto-economic security framework ultimately conjured and enforced by economic incentives and punishments. To do twice as much work with the same levels of security and no special coordination between validator sets, then such systems essentially prescribe forming a new network with the same overall levels of incentivization.

Several problems arise. Firstly, there is a similar downside as with Polkadot’s isolated parachains and Ethereum’s isolated roll-up chains: a lack of coherency due to a persistently sharded state preventing synchronous composability.

More problematically, the scaling-by-fragmentation approach, proposed specifically by Cosmos, provides no homogenous security—and therefore trustlessness—guarantees. Validator sets between networks must be assumed to be independently selected and incentivized with no relationship, causal or probabilistic, between the Byzantine actions of a party on one network and potential for appropriate repercussions on another. Essentially, this means that should validators conspire to corrupt or revert the state of one network, the effects may be felt across other networks of the ecosystem.

That this is an issue is broadly accepted, and projects propose for it to be addressed in one of two ways. Firstly, to fix the expected cost-of-attack (and thus level of security) across networks by drawing from the same validator set. The massively redundant way of doing this, as proposed by under the name *replicated security*, would be to require each validator to validate on all networks and for the same incentives and punishments. This is economically inefficient in the cost of security provision as each network would need to independently provide the same level of incentives and punishment-requirements as the most secure with which it wanted to interoperate. This is to ensure the economic proposition remain unchanged for validators and the security proposition remained equivalent for all networks. At the present time, replicated security is not a readily available permissionless service. We might speculate that these punishing economics have something to do with it.

The more efficient approach, proposed by the OmniLedger team, , would be to make the validators non-redundant, partitioning them between different networks and periodically, securely and randomly repartitioning them. A reduction in the cost to attack over having them all validate on a single network is implied since there is a chance of having a single network accidentally have a compromising number of malicious validators even with less than this proportion overall. This aside it presents an effective means of scaling under a basis of weak-coherency.

Alternatively, as in ELVES by , we may utilize non-redundant partitioning, combine this with a proposal-and-auditing game which validators play to weed out and punish invalid computations, and then require that the finality of one network be contingent on all causally-entangled networks. This is the most secure and economically efficient solution of the three, since there is a mechanism for being highly confident that invalid transitions will be recognized and corrected before their effect is finalized across the ecosystem of networks. However, it requires substantially more sophisticated logic and their causal-entanglement implies some upper limit on the number of networks which may be added.

## High-Performance Fully Synchronous Networks

Another trend in the recent years of blockchain development has been to make “tactical” optimizations over data throughput by limiting the validator set size or diversity, focusing on software optimizations, requiring a higher degree of coherency between validators, onerous requirements on the hardware which validators must have, or limiting data availability.

The Solana blockchain is underpinned by technology introduced by and boasts theoretical figures of over 700,000 transactions per second, though according to the network is only seen processing a small fraction of this. The underlying throughput is still substantially more than most blockchain networks and is owed to various engineering optimizations in favor of maximizing synchronous performance. The result is a highly-coherent smart-contract environment with an API not unlike that of *YP* Ethereum (albeit using a different underlying VM), but with a near-instant time to inclusion and finality which is taken to be immediate upon inclusion.

Two issues arise with such an approach: firstly, defining the protocol as the outcome of a heavily optimized codebase creates structural centralization and can undermine resilience. writes “since January 2022, 11 significant outages gave rise to 15 days in which major or partial outages were experienced”. This is an outlier within the major blockchains as the vast majority of major chains have no downtime. There are various causes to this downtime, but they are generally due to bugs found in various subsystems.

Ethereum, at least until recently, provided the most contrasting alternative with its well-reviewed specification, clear research over its crypto-economic foundations and multiple clean-room implementations. It is perhaps no surprise that the network very notably continued largely unabated when a flaw in its most deployed implementation was found and maliciously exploited, as described by .

The second issue is concerning ultimate scalability of the protocol when it provides no means of distributing workload beyond the hardware of a single machine.

In major usage, both historical transaction data and state would grow impractically. Solana illustrates how much of a problem this can be. Unlike classical blockchains, the Solana protocol offers no solution for the archival and subsequent review of historical data, crucial if the present state is to be proven correct from first principle by a third party. There is little information on how Solana manages this in the literature, but according to , nodes simply place the data onto a centralized database hosted by Google.[^6]

Solana validators are encouraged to install large amounts of RAM to help hold its large state in memory (512 GB is the current recommendation according to ). Without a divide-and-conquer approach, Solana shows that the level of hardware which validators can reasonably be expected to provide dictates the upper limit on the performance of a totally synchronous, coherent execution model. Hardware requirements represent barriers to entry for the validator set and cannot grow without sacrificing decentralization and, ultimately, transparency.

# Notational Conventions

Much as in the Ethereum Yellow Paper, a number of notational conventions are used throughout the present work. We define them here for clarity. The Ethereum Yellow Paper itself may be referred to henceforth as the *YP*.

## Typography

We use a number of different typefaces to denote different kinds of terms. Where a term is used to refer to a value only relevant within some localized section of the document, we use a lower-case roman letter $x$, $y$ (typically used for an item of a set or sequence) or $i$, $j$ (typically used for numerical indices). Where we refer to a Boolean term or a function in a local context, we tend to use a capitalized roman alphabet letter such as $A$, $F$. If particular emphasis is needed on the fact a term is sophisticated or multidimensional, then we may use a bold typeface, especially in the case of sequences and sets.

For items which retain their definition throughout the present work, we use other typographic conventions. Sets are usually referred to with a blackboard typeface, $\N$ refers to all natural numbers including zero. Sets which may be parameterized may be subscripted or be followed by parenthesized arguments. Imported functions, used by the present work but not specifically introduced by it, are written in calligraphic typeface, $\fnblake$ the Blake2 cryptographic hashing function. For other non-context dependent functions introduced in the present work, we use upper case Greek letters, $\transitionstate$ denotes the state transition function.

Values which are not fixed but nonetheless hold some consistent meaning throughout the present work are denoted with lower case Greek letters such as $\thestate$, the state identifier. These may be placed in bold typeface to denote that they refer to an abnormally complex value.

## Functions and Operators

We define the precedes relation to indicate that one term is defined in terms of another. $y \prec x$ indicates that $y$ may be defined purely in terms of $x$: $$\begin{aligned}
\label{eq:precedes}
  y \prec x \Longleftrightarrow \exists f: y = f(x)
\end{aligned}$$

The substitute-if-nothing function $\fnsubifnone$ is equivalent to the first argument which is not $\none$, or $\none$ if no such argument exists: $$\begin{aligned}
\label{eq:substituteifnothing}
  \subifnone{a_0, \dots a\sub{n}} \equiv a\sub{x} : (a\sub{x} \ne \none \vee x = n), \bigwedge_{i=0}^{x-1} a\sub{i} = \none
\end{aligned}$$ Thus, $\subifnone{\none, 1, \none, 2} = 1$ and $\subifnone{\none, \none} = \none$.

## Sets

Given some set $\mathbf{s}$, its power set and cardinality are denoted as $\protoset{s}$ and $\len{\mathbf{s}}$. When forming a power set, we may use a numeric subscript in order to restrict the resultant expansion to a particular cardinality. $\protoset{\set{1, 2, 3}}_2 = \set{ \set{1, 2}, \set{1, 3}, \set{2, 3} }$.

Sets may be operated on with scalars, in which case the result is a set with the operation applied to each element, $\set{1, 2, 3} + 3 = \set{4, 5, 6}$. Functions may also be applied to all members of a set to yield a new set, but for clarity we denote this with a $\#$ superscript, $f^{\#}(\set{1, 2}) \equiv \set{f(1), f(2)}$.

We denote set-disjointness with the relation $\disjoint$. Formally: $$A \cap B = \none \Longleftrightarrow A \disjoint B$$

We commonly use $\none$ to indicate that some term is validly left without a specific value. Its cardinality is defined as zero. We define the operation $\optional{}$ such that $\optional{A} \equiv A \cup \set{\none}$ indicating the same set but with the addition of the $\none$ element.

The term $\error$ is utilized to indicate the unexpected failure of an operation or that a value is invalid or unexpected. (We try to avoid the use of the more conventional $\bot$ here to avoid confusion with Boolean false, which may be interpreted as some successful result in some contexts.)

## Numbers

$\N$ denotes the set of naturals including zero whereas $\Nmax{n}$ implies a restriction on that set to values less than $n$. Formally, $\N = \set{0, 1, \dots}$ and $\Nmax{n} = \set{\build{x}{x \in \N, x < n}}$.

$\Z$ denotes the set of integers. We denote $\Z\interval{a}{b}$ to be the set of integers within the interval $[a, b)$. Formally, $\Z\interval{a}{b} = \set{\build{x}{x \in \Z, a \le x < b}}$. $\Z\interval{2}{5} = \set{2, 3, 4}$. We denote the offset/length form of this set as $\Z\subrange{a}{b}$, a short form of $\Z\interval{a}{a+b}$.

It can sometimes be useful to represent lengths of sequences and yet limit their size, especially when dealing with sequences of octets which must be stored practically. Typically, these lengths can be defined as the set $\Nbits{32}$. To improve clarity, we denote $\bloblength$ as the set of lengths of octet sequences and is equivalent to $\Nbits{32}$.

We denote the $\rem$ operator as the modulo operator, $5 \rem 3 = 2$. Furthermore, we may occasionally express a division result as a quotient and remainder with the separator $\remainder$, $5 \div 3 = 1 \remainder 2$.

## Dictionaries

A *dictionary* is a possibly partial mapping from some domain into some co-domain in much the same manner as a regular function. Unlike functions however, with dictionaries the total set of pairings are necessarily enumerable, and we represent them in some data structure as the set of all $\kv{key}{value}$ pairs. (In such data-defined mappings, it is common to name the values within the domain a *key* and the values within the co-domain a *value*, hence the naming.)

Thus, we define the formalism $\dictionary{\mathrm{K}}{\mathrm{V}}$ to denote a dictionary which maps from the domain $\mathrm{K}$ to the range $\mathrm{V}$. It is a subset of the power set of pairs $\tuple{K, V}$: $$\dictionary{\mathrm{K}}{\mathrm{V}} \subset \protoset{\tuple{\mathrm{K}, \mathrm{V}}}$$

The subset is caused by a constraint that a dictionary’s members must associate at most one unique value for any given key $k$: $$\forall \mathrm{K}, \mathrm{V}, \mathbf{d} \in \dictionary{\mathrm{K}}{\mathrm{V}} : \forall \tup{k, v} \in \mathbf{d} : \exists! v' : \tup{k, v'} \in \mathbf{d}$$

In the context of a dictionary we denote the pairs with a mapping notation: $$\begin{aligned}
  &\dictionary{\mathrm{K}}{\mathrm{V}} \equiv \protoset{\keyvalue{\mathrm{K}}{\mathrm{V}}}\\
  &\mathbf{p} \in \keyvalue{\mathrm{K}}{\mathrm{V}} \Leftrightarrow \exists k \in \mathrm{K}, v \in \mathrm{V}, \mathbf{p} \equiv \kv{k}{v}
\end{aligned}$$

This assertion allows us to unambiguously define the subscript and subtraction operator for a dictionary $d$: $$\begin{aligned}
  &\forall \mathrm{K}, \mathrm{V}, \mathbf{d} \in \dictionary{\mathrm{K}}{\mathrm{V}}: \mathbf{d}\subb{k} \equiv \begin{cases}
    v & \text{if}\ \exists k : \kv{k}{v} \in \mathbf{d} \\
    \none & \otherwise
  \end{cases}\\
  &\begin{aligned}
    &\forall \mathrm{K}, \mathrm{V}, \mathbf{d} \in \dictionary{\mathrm{K}}{\mathrm{V}}, \mathbf{s} \subseteq K:\\
    &\quad \mathbf{d} \setminus \mathbf{s} \equiv \set{ \kv{k}{v}: \kv{k}{v} \in \mathbf{d}, k \not\in \mathbf{s} }
  \end{aligned}
\end{aligned}$$

Note that when using a subscript, it is an implicit assertion that the key exists in the dictionary. Should the key not exist, the result is undefined and any block which relies on it must be considered invalid.

To denote the active domain (set of keys) of a dictionary $\mathbf{d} \in \dictionary{K}{V}$, we use $\keys{\mathbf{d}} \subseteq K$ and for the range (set of values), $\values{\mathbf{d}} \subseteq V$. Formally: $$\begin{aligned}
  \forall \mathrm{K}, \mathrm{V}, \mathbf{d} \in \dictionary{\mathrm{K}}{\mathrm{V}} : \keys{\mathbf{d}} &\equiv \set{\build{k}{\exists v : \kv{k}{v} \in \mathbf{d}}} \\
  \forall \mathrm{K}, \mathrm{V}, \mathbf{d} \in \dictionary{\mathrm{K}}{\mathrm{V}} : \values{\mathbf{d}} &\equiv \set{\build{v}{\exists k : \kv{k}{v} \in \mathbf{d}}}
\end{aligned}$$

Note that since the co-domain of $\values{}$ is a set, should different keys with equal values appear in the dictionary, the set will only contain one such value.

Dictionaries may be combined through the union operator $\cup$, which priorities the right-side operand in the case of a key-collision: $$\forall \mathbf{d} \in \mathrm{K}, \mathrm{V}, \tup{\mathbf{d}, \mathbf{e}} \in \dictionary{\mathrm{K}}{\mathrm{V}}^2 : \mathbf{d} \cup \mathbf{e} \equiv (\mathbf{d} \setminus \keys{\mathbf{e}}) \cup \mathbf{e}$$

## Tuples

Tuples are groups of values where each item may belong to a different set. They are denoted with parentheses, the tuple $t$ of the naturals $3$ and $5$ is denoted $t = \tup{3, 5}$, and it exists in the set of natural pairs sometimes denoted $\N \times \N$, but denoted in the present work as $\tuple{\N, \N}$.

We have frequent need to refer to a specific item within a tuple value and as such find it convenient to declare a name for each item. we may denote a tuple with two named natural components $a$ and $b$ as $T = \tuple{\isa{a}{\N},\,\isa{b}{\N}}$. We would denote an item $t \in T$ through subscripting its name, thus for some $t = \tup{\is{a}{3},\,\is{b}{5}}$, $t_{a} = 3$ and $t_{b} = 5$.

## Sequences

A sequence is a series of elements with particular ordering not dependent on their values. The set of sequences of elements all of which are drawn from some set $T$ is denoted $\sequence{T}$, and it defines a partial mapping $\N \to T$. The set of sequences containing exactly $n$ elements each a member of the set $T$ may be denoted $\sequence[n]{T}$ and accordingly defines a complete mapping $\Nmax{n} \to T$. Similarly, sets of sequences of at most $n$ elements and at least $n$ elements may be denoted $\sequence[:n]{T}$ and $\sequence[n:]{T}$ respectively.

Sequences are subscriptable, thus a specific item at index $i$ within a sequence $\mathbf{s}$ may be denoted $\mathbf{s}\subb{i}$, or where unambiguous, $\mathbf{s}\sub{i}$. A range may be denoted using an ellipsis for example: $\sq{0, 1, 2, 3}\sub{\dots2} = \sq{0, 1}$ and $\sq{0, 1, 2, 3}\sub{1\dots+2} = \sq{1, 2}$. The length of such a sequence may be denoted $\len{\mathbf{s}}$.

We denote modulo subscription as $\cyclic{\mathbf{s}\subb{i}} \equiv \mathbf{s}[\,i \rem \len{\mathbf{s}}\,]$. We denote the final element $x$ of a sequence $\mathbf{s} = \sq{..., x}$ through the function $\text{last}(\mathbf{s}) \equiv x$.

### Construction

We may wish to define a sequence in terms of incremental subscripts of other values: $\sq{\mathbf{x}_0, \mathbf{x}_1, \dots }\sub{\dots n}$ denotes a sequence of $n$ values beginning $\mathbf{x}_0$ continuing up to $\mathbf{x}_{n-1}$. Furthermore, we may also wish to define a sequence as elements each of which are a function of their index $i$; in this case we denote $\sq{\build{f(i)}{i \orderedin \Nmax{n}}} \equiv \sq{f(0), f(1), \dots, f(n - 1)}$. Thus, when the ordering of elements matters we use $\orderedin$ rather than the unordered notation $\in$. The latter may also be written in short form $\sq{f(i \orderedin \Nmax{n})}$. This applies to any set which has an unambiguous ordering, particularly sequences, thus $\sq{\build{i^2}{i \orderedin \sq{1, 2, 3}}} = \sq{1, 4, 9}$. Multiple sequences may be combined, thus $\sq{\build{i \cdot j}{i \orderedin \sq{1, 2, 3}, j \orderedin \sq{2, 3, 4}}} = \sq{2, 6, 12}$.

As with sets, we use explicit notation $f^{\#}$ to denote a function mapping over all items of a sequence.

Sequences may be constructed from sets or other sequences whose order should be ignored through sequence ordering notation $\sqorderby{f(i)}{i \in X}$, which is defined to result in the set or sequence of its argument except that all elements $i$ are placed in ascending order of the corresponding value $f(i)$.

The key component may be elided in which case it is assumed to be ordered by the elements directly; $\order{i \in X} \equiv \sqorderby{i}{i \in X}$. $\sqorderuniqby{i}{i \in X}$ does the same, but excludes any duplicate values of $i$. assuming $\mathbf{s} = \sq{1, 3, 2, 3}$, then $\sqorderuniqby{i}{i \in \mathbf{s}} = \sq{1, 2, 3}$ and $\sqorderby{-i}{i \in \mathbf{s}} = \sq{3, 3, 2, 1}$.

Sets may be constructed from sequences with the regular set construction syntax, assuming $\mathbf{s} = \sq{1, 2, 3, 1}$, then $\set{\build{a}{a \in \mathbf{s}}}$ would be equivalent to $\set{1, 2, 3}$.

Sequences of values which themselves have a defined ordering have an implied ordering akin to a regular dictionary, thus $\sq{1, 2, 3} < \sq{1, 2, 4}$ and $\sq{1, 2, 3} < \sq{1, 2, 3, 1}$.

### Editing

We define the sequence concatenation operator $\concat$ such that $\sq{\mathbf{x}_0, \mathbf{x}_1, \dots, \mathbf{y}_0, \mathbf{y}_1, \dots} \equiv \mathbf{x} \concat \mathbf{y}$. For sequences of sequences, we define a unary concatenate-all operator: $\concatall{\mathbf{x}}\equiv\mathbf{x}_0 \concat \mathbf{x}_1 \concat \dots$. Further, we denote element concatenation as $x \append i \equiv x \concat \sq{i}$. We denote the sequence made up of the first $n$ elements of sequence $\mathbf{s}$ to be ${\overrightarrow{\mathbf{s}}}^n \equiv \sq{\mathbf{s}_0, \mathbf{s}_1, \dots, \mathbf{s}_{n-1}}$, and only the final elements as ${\overleftarrow{\mathbf{s}}}^n$.

We define ${}^\text{T}\mathbf{x}$ as the transposition of the sequence-of-sequences $\mathbf{x}$, fully defined in equation eq:transpose. We may also apply this to sequences-of-tuples to yield a tuple of sequences.

We denote sequence subtraction with a slight modification of the set subtraction operator; specifically, some sequence $\mathbf{s}$ excepting the left-most element equal to $v$ would be denoted $\mathbf{s}\seqminusl\set{v}$.

### Boolean values

$\bitstring[s]$ denotes the set of Boolean strings of length $s$, thus $\bitstring[s] = \sequence[s]{\bool}$. When dealing with Boolean values we may assume an implicit equivalence mapping to a bit whereby $\top = 1$ and $\bot = 0$, thus $\bitstring[\Box] = \sequence[\Box]{\N_2}$. We use the function $\text{bits}(\blob) \in \bitstring$ to denote the sequence of bits, ordered with the most significant first, which represent the octet sequence $\blob$, thus $\text{bits}(\sq{160, 0}) = \sq{1, 0, 1, 0, 0, \dots}$.

The unary-not operator applies to both boolean values and sequences of boolean values, thus $\neg \top = \bot$ and $\neg \sq{\top, \bot} = \sq{\bot, \top}$.

### Octets and Blobs

$\blob$ denotes the set of octet strings (“blobs”) of arbitrary length. As might be expected, $\blob[x]$ denotes the set of such sequences of length $x$. $\blob[\$]$ denotes the subset of $\blob$ which are ASCII-encoded strings. Note that while an octet has an implicit and obvious bijective relationship with natural numbers less than 256, and we may implicitly coerce between octet form and natural number form, we do not treat them as exactly equivalent entities. In particular for the purpose of serialization, an octet is always serialized to itself, whereas a natural number may be serialized as a sequence of potentially several octets, depending on its magnitude and the encoding variant.

### Shuffling

We define the sequence-shuffle function $\fnfyshuffle$, originally introduced by , with an efficient in-place algorithm described by . This accepts a sequence and some entropy and returns a sequence of the same length with the same elements but in an order determined by the entropy. The entropy may be provided as either an indefinite sequence of naturals or a hash. For a full definition see appendix 28.

## Cryptography

### Hashing

$\hash$ denotes the set of 256-bit values equivalent to $\blob[32]$. All hash functions in the present work output to this type and $\zerohash$ is the value equal to $\sq{0}_{32}$. We assume a function $\blake{m \in \blob} \in \hash$ denoting the Blake2b 256-bit hash introduced by and a function $\keccak{m \in \blob} \in \hash$ denoting the Keccak 256-bit hash as proposed by and utilized by .

The inputs of a hash function should be expected to be passed through our serialization codec $\mathcal{E}$ to yield an octet sequence to which the cryptography may be applied. (Note that an octet sequence conveniently yields an identity transform.) We may wish to interpret a sequence of octets as some other kind of value with the assumed decoder function $\decode{x \in \blob}$. In both cases, we may subscript the transformation function with the number of octets we expect the octet sequence term to have. Thus, $r = \mathcal{E}_4(x \in \N)$ would assert $x \in \Nbits{32}$ and $r \in \blob[4]$, whereas $s = \decode[8]{y}$ would assert $y \in \blob[8]$ and $s \in \Nbits{64}$.

### Signing Schemes

$\edsignature{k}{m} \subset \blob[64]$ is the set of valid Ed25519 signatures, defined by , made through knowledge of a secret key whose public key counterpart is $k \in \hash$ and whose message is $m$. To aid readability, we denote the set of valid public keys $\edkey$.

We denote the set of valid Bandersnatch public keys as $\bskey$, defined in appendix 29. $\bssignature{k \in \bskey}{x \in \blob}{m \in \blob} \subset \blob[96]$ is the set of valid singly-contextualized signatures of utilizing the secret counterpart to the public key $k$, some context $x$ and message $m$.

$\bsringproof{r \in \ringroot}{x \in \blob}{m \in \blob} \subset \blob[784]$, meanwhile, is the set of valid Bandersnatch RingVRF deterministic singly-contextualized proofs of knowledge of a secret within some set of secrets identified by some root in the set of valid *roots* $\ringroot \subset \blob[144]$. We denote $\getringroot{\mathbf{s} \in \sequence{\bskey}} \in \ringroot$ to be the root specific to the set of public key counterparts $\mathbf{s}$. A root implies a specific set of Bandersnatch key pairs, knowledge of one of the secrets would imply being capable of making a unique, valid—and anonymous—proof of knowledge of a unique secret within the set.

Both the Bandersnatch signature and RingVRF proof strictly imply that a member utilized their secret key in combination with both the context $x$ and the message $m$; the difference is that the member is identified in the former and is anonymous in the latter. Furthermore, both define a VRF *output*, a high entropy hash influenced by $x$ but not by $m$, formally denoted $\banderout{\bsringproof{r}{x}{m}} \subset \hash$ and $\banderout{\bssignature{k}{x}{m}} \subset \hash$.

We use $\blskey \subset \blob[144]$ to denote the set of public keys for the BLS signature scheme, described by , on curve BLS- defined by . We correspondingly use the notation $\blssignature{k}{m}$ to denote the set of valid BLS signatures for public key $k \in \blskey$ and message $m \in \blob$.

We define the signature functions for creating valid signatures; $\edsigndata{k}{m} \in \edsignature{k}{m}$, $\blssigndata{k}{m} \in \blssignature{k}{m}$. We assert that the ability to compute a result for this function relies on knowledge of a secret key.

# Overview

As in the Yellow Paper, we begin our formalisms by recalling that a blockchain may be defined as a pairing of some initial state together with a block-level state-transition function. The latter defines the posterior state given a pairing of some prior state and a block of data applied to it. Formally, we say: $$\begin{aligned}
\label{eq:statetransition}
\thestate' \equiv \transitionstate(\thestate, \block)
\end{aligned}$$

Where $\thestate$ is the prior state, $\thestate'$ is the posterior state, $B$ is some valid block and $\transitionstate$ is our block-level state-transition function.

Broadly speaking, (and indeed blockchains in general) may be defined simply by specifying $\transitionstate$ and some *genesis state* $\thestate^0$.[^7] We also make several additional assumptions of agreed knowledge: a universally known clock, and the practical means of sharing data with other systems operating under the same consensus rules. The latter two were both assumptions silently made in the *YP*.

## The Block

To aid comprehension and definition of our protocol, we partition as many of our terms as possible into their functional components. We begin with the block $\block$ which may be restated as the header $\H$ and some input data external to the system and thus said to be *extrinsic*, $\extrinsic$: $$\begin{aligned}
  \label{eq:block}\block &\equiv \tup{\header, \extrinsic} \\
  \label{eq:extrinsic}\extrinsic &\equiv \tup{\xttickets, \xtdisputes, \xtpreimages, \xtassurances, \xtguarantees}
\end{aligned}$$

The header is a collection of metadata primarily concerned with cryptographic references to the blockchain ancestors and the operands and result of the present transition. As an immutable known *a priori*, it is assumed to be available throughout the functional components of block transition. The extrinsic data is split into its several portions:

tickets  
Tickets, used for the mechanism which manages the selection of validators for the permissioning of block authoring. This component is denoted $\xttickets$.

preimages  
Static data which is presently being requested to be available for workloads to be able to fetch on demand. This is denoted $\xtpreimages$.

reports  
Reports of newly completed workloads whose accuracy is guaranteed by specific validators. This is denoted $\xtguarantees$.

availability  
Assurances by each validator concerning which of the input data of workloads they have correctly received and are storing locally. This is denoted $\xtassurances$.

disputes  
Information relating to disputes between validators over the validity of reports. This is denoted $\xtdisputes$.

## The State

Our state may be logically partitioned into several largely independent segments which can both help avoid visual clutter within our protocol description and provide formality over elements of computation which may be simultaneously calculated (i.e. parallelized). We therefore pronounce an equivalence between $\thestate$ (some complete state) and a tuple of partitioned segments of that state: $$\begin{aligned}
\label{eq:statecomposition}
  \thestate &\equiv \tup{\authpool, \recent, \lastaccout, \safrole, \accounts, \entropy, \stagingset, \activeset, \previousset, \reports, \thetime, \authqueue, \privileges, \disputes, \activity, \ready, \accumulated}
\end{aligned}$$

In summary, $\accounts$ is the portion of state dealing with *services*, analogous in to the Yellow Paper’s (smart contract) *accounts*, the only state of the *YP*’s Ethereum. The identities of services which hold some privileged status are tracked in $\privileges$.

Validators, who are the set of economic actors uniquely privileged to help build and maintain the chain, are identified within $\activeset$, archived in $\previousset$ and enqueued from $\stagingset$. All other state concerning the determination of these keys is held within $\safrole$. Note this is a departure from the *YP* proof-of-work definitions which were mostly stateless, and this set was not enumerated but rather limited to those with sufficient compute power to find a partial hash-collision in the SHA- cryptographic hash function. An on-chain entropy pool is retained in $\entropy$.

Our state also tracks two aspects of each core: $\authpool$, the authorization requirement which work done on that core must satisfy at the time of being reported on-chain, together with the queue which fills this, $\authqueue$; and $\reports$, each of the cores’ currently assigned *report*, the availability of whose *work-package* must yet be assured by a super-majority of validators.

Finally, details of the most recent blocks and timeslot index are tracked in $\recenthistory$ and $\thetime$ respectively, work-reports which are ready to be accumulated and work-packages which were recently accumulated are tracked in $\ready$ and $\accumulated$ respectively and, judgments are tracked in $\disputes$ and validator statistics are tracked in $\activity$.

### State Transition Dependency Graph

Much as in the *YP*, we specify $\transitionstate$ as the implication of formulating all items of posterior state in terms of the prior state and block. To aid the architecting of implementations which parallelize this computation, we minimize the depth of the dependency graph where possible. The overall dependency graph is specified here: $$\begin{aligned}
\label{eq:transitionfunctioncomposition}
  \thetime' &\prec \theheader \\
  \recenthistorypostparentstaterootupdate &\prec \tup{\theheader, \recenthistory} \label{eq:betadagger} \\
  \safrole' &\prec \tup{\theheader, \thetime, \xttickets, \safrole, \stagingset, \entropy', \activeset', \disputes'} \\
  \entropy' &\prec \tup{\theheader, \thetime, \entropy} \\
  \activeset' &\prec \tup{\theheader, \thetime, \activeset, \safrole} \\
  \previousset' &\prec \tup{\theheader, \thetime, \previousset, \activeset} \\
  \disputes' &\prec \tup{\xtdisputes, \disputes} \\
  \reportspostjudgement &\prec \tup{\xtdisputes, \reports} \label{eq:rhodagger} \\
  \reportspostguarantees &\prec \tup{\xtassurances, \reportspostjudgement} \label{eq:rhoddagger} \\
  \reports' &\prec \tup{\xtguarantees, \reportspostguarantees, \activeset, \thetime'} \label{eq:rhoprime} \\
  \justbecameavailable^* &\prec \tup{\xtassurances, \reportspostjudgement} \\
  \tup{\ready', \accumulated', \accountspostxfer, \privileges', \stagingset', \authqueue', \lastaccout', \accumulationstatistics} &\prec \tup{\justbecameavailable^*, \ready, \accumulated, \accountspre, \privileges, \stagingset, \authqueue, \thetime, \thetime'} \label{eq:accountspostxfer} \\
  \recenthistory' &\prec \tup{\theheader, \xtguarantees, \recenthistorypostparentstaterootupdate, \lastaccout'} \label{eq:betaprime} \\
  \accountspostpreimage &\prec \tup{\xtpreimages, \accountspostxfer, \thetime'} \label{eq:accountspostpreimage} \\
  \authpool' &\prec \tup{\theheader, \xtguarantees, \authqueue', \authpool} \\
  \activity' &\prec \tup{\xtguarantees, \xtpreimages, \xtassurances, \xttickets, \thetime, \activeset', \activity, \theheader, \accumulationstatistics}\!\!\!\!\!\!\!\!
\end{aligned}$$

The only synchronous entanglements are visible through the intermediate components superscripted with a dagger and defined in equations eq:betadagger, eq:rhodagger, eq:rhoddagger, eq:rhoprime, eq:accountspostxfer, eq:betaprime and eq:accountspostpreimage. The latter two mark a merge and join in the dependency graph and, concretely, imply that the availability extrinsic may be fully processed and accumulation of work happen before the preimage lookup extrinsic is folded into state.

## Which History?

A blockchain is a sequence of blocks, each cryptographically referencing some prior block by including a hash of its header, all the way back to some first block which references the genesis header. We already presume consensus over this genesis header $\theheader^0$ and the state it represents already defined as $\thestate^0$.

By defining a deterministic function for deriving a single posterior state for any (valid) combination of prior state and block, we are able to define a unique *canonical* state for any given block. We generally call the block with the most ancestors the *head* and its state the *head state*.

It is generally possible for two blocks to be valid and yet reference the same prior block in what is known as a *fork*. This implies the possibility of two different heads, each with their own state. While we know of no way to strictly preclude this possibility, for the system to be useful we must nonetheless attempt to minimize it. We therefore strive to ensure that:

1.  It be generally unlikely for two heads to form.

2.  When two heads do form they be quickly resolved into a single head.

3.  It be possible to identify a block not much older than the head which we can be extremely confident will form part of the blockchain’s history in perpetuity. When a block becomes identified as such we call it *finalized* and this property naturally extends to all of its ancestor blocks.

These goals are achieved through a combination of two consensus mechanisms: *Safrole*, which governs the (not-necessarily forkless) extension of the blockchain; and *Grandpa*, which governs the finalization of some extension into canonical history. Thus, the former delivers point enum:wh:minimize, the latter delivers point enum:wh:finalize and both are important for delivering point enum:wh:resolve. We describe these portions of the protocol in detail in sections 6 and sec:grandpa respectively.

While Safrole limits forks to a large extent (through cryptography, economics and common-time, below), there may be times when we wish to intentionally fork since we have come to know that a particular chain extension must be reverted. In regular operation this should never happen, however we cannot discount the possibility of malicious or malfunctioning nodes. We therefore define such an extension as any which contains a block in which data is reported which *any other* block’s state has tagged as invalid (see section 10 on how this is done). We further require that Grandpa not finalize any extension which contains such a block. See section 19 for more information here.

## Time

We presume a pre-existing consensus over time specifically for block production and import. While this was not an assumption of Polkadot, pragmatic and resilient solutions exist including the NTP protocol and network. We utilize this assumption in only one way: we require that blocks be considered temporarily invalid if their timeslot is in the future. This is specified in detail in section 6.

Formally, we define the time in terms of seconds passed since the beginning of the *Common Era*, 1200 UTC on January 1, 2025.[^8] Midday UTC is selected to ensure that all major timezones are on the same date at any exact 24-hour multiple from the beginning of the common era. Formally, this value is denoted $\wallclock$.

## Best block

Given the recognition of a number of valid blocks, it is necessary to determine which should be treated as the “best” block, by which we mean the most recent block we believe will ultimately be within of all future chains. The simplest and least risky means of doing this would be to inspect the Grandpa finality mechanism which is able to provide a block for which there is a very high degree of confidence it will remain an ancestor to any future chain head.

However, in reducing the risk of the resulting block ultimately not being within the canonical chain, Grandpa will typically return a block some small period older than the most recently authored block. (Existing deployments suggest around 1-2 blocks in the past under regular operation.) There are often circumstances when we may wish to have less latency at the risk of the returned block not ultimately forming a part of the future canonical chain. we may be in a position of being able to author a block, and we need to decide what its parent should be. Alternatively, we may care to speculate about the most recent state for the purpose of providing information to a downstream application reliant on the state of .

In these cases, we define the best block as the head of the best chain, itself defined in section 19.

## Economics

The present work describes a crypto-economic system, one combining elements of both cryptography and economics and game theory to deliver a self-sovereign digital service. In order to codify and manipulate economic incentives we define a token which is native to the system, which we will simply call *tokens* in the present work.

A value of tokens is generally referred to as a *balance*, and such a value is said to be a member of the set of balances, $\balance$, which is exactly equivalent to the set of naturals less than $2^{64}$ (-bit unsigned integers in coding parlance). Formally: $$\begin{aligned}
\label{eq:balance}
  \balance \equiv \Nbits{64}
\end{aligned}$$

Though unimportant for the present work, we presume that there be a standard named denomination for $10^{9}$ tokens. This is different to both Ethereum (which uses a denomination of $10^{18}$), Polkadot (which uses a denomination of $10^{10}$) and Polkadot’s experimental cousin Kusama (which uses $10^{12}$).

The fact that balances are constrained to being less than $2^{64}$ implies that there may never be more than around $18\times10^{9}$ tokens (each divisible into portions of $10^{-9}$) within . We would expect that the total number of tokens ever issued will be a substantially smaller amount than this.

We further presume that a number of constant *prices* stated in terms of tokens are known. However we leave the specific values to be determined in following work:

<div class="description">

the additional minimum balance implied for a single item within a mapping.

the additional minimum balance implied for a single octet of data within a mapping.

the minimum balance implied for a service.

</div>

## The Virtual Machine and Gas

In the present work, we presume the definition of a *Polkadot Virtual Machine* (PVM). This virtual machine is based around the RISC-V instruction set architecture, specifically the RVEM variant, and is the basis for introducing permissionless logic into our state-transition function.

The PVM is comparable to the EVM defined in the Yellow Paper, but somewhat simpler: the complex instructions for cryptographic operations are missing as are those which deal with environmental interactions. Overall it is far less opinionated since it alters a pre-existing general purpose design, RISC-V, and optimizes it for our needs. This gives us excellent pre-existing tooling, since PVM remains essentially compatible with RISC-V, including support from the compiler toolkit LLVM and languages such as Rust and C++. Furthermore, the instruction set simplicity which RISC-V and PVM share, together with the register size (64-bit), active number (13) and endianness (little) make it especially well-suited for creating efficient recompilers on to common hardware architectures.

The PVM is fully defined in appendix 23, but for contextualization we will briefly summarize the basic invocation function $\Psi$ which computes the resultant state of a PVM instance initialized with some registers ($\sequence[13]{\pvmreg}$) and RAM ($\ram$) and has executed for up to some amount of gas ($\gas$), a number of approximately time-proportional computational steps: $$\Psi\colon
  \tuple{\,
    \begin{alignedat}{3}
      &\blob,\,\ \ \pvmreg,\,\ \ &&\gas,\,\\
      &\!\sequence[13]{\pvmreg},\,\ \ &&\ram\\
    \end{alignedat}
  \,}
  \to
  \tuple{\,
    \begin{aligned}
      &\set{\halt, \panic, \oog} \cup \set{\fault,\host} \times \pvmreg,\\
      &\pvmreg,\ \ \signedgas,\ \ \sequence[13]{\pvmreg},\ \ \ram
    \end{aligned}
  \,}$$

We refer to the time-proportional computational steps as *gas* (much like in the *YP*) and limit it to a 64-bit quantity. We may use either $\gas$ or $\signedgas$ to bound it, the first as a prior argument since it is known to be positive, the latter as a result where a negative value indicates an attempt to execute beyond the gas limit. Within the context of the PVM, $\gascounter \in \gas$ is typically used to denote gas. $$\label{eq:gasregentry}
  \signedgas \equiv \Z_{-2^{63}\dots2^{63}}\ ,\quad
  \gas \equiv \Nbits{64}\ ,\quad
  \pvmreg \equiv \Nbits{64}$$

It is left as a rather important implementation detail to ensure that the amount of time taken while computing the function $\Psi(\dots, \gascounter, \dots)$ has a maximum computation time approximately proportional to the value of $\gascounter$ regardless of other operands.

The PVM is a very simple RISC *register machine* and as such has 13 registers, each of which is a 64-bit quantity, denoted as $\pvmreg$, a natural less than $2^{64}$.[^9] Within the context of the PVM, $\registers \in \sequence[13]{\pvmreg}$ is typically used to denote the registers. $$\begin{aligned}
\label{eq:pvmmemory}
  \ram &\equiv \tuple{
    \isa{\ramSUBvalue}{\blob[2^{32}]},
    \isa{\ramSUBaccess}{\sequence[p]{\set{\text{W}, \text{R}, \none}}}
  }\,,\ p = \frac{2^{32}}{\Cpvmpagesize}\\
  \Cpvmpagesize &= 2^{12}
\end{aligned}$$

The PVM assumes a simple pageable RAM of 32-bit addressable octets situated in pages of $\Cpvmpagesize = 4096$ octets where each page may be either immutable, mutable or inaccessible. The RAM definition $\ram$ includes two components: a value $\ramSUBvalue$ and access $\ramSUBaccess$. If the component is unspecified while being subscripted then the value component may be assumed. Within the context of the virtual machine, $\memory \in \ram$ is typically used to denote RAM. $$\begin{aligned}
  \readable{\memory} &\equiv \set{\build{i}{\memory_\ramSUBaccess\subb{\floor{\nicefrac{i}{\Cpvmpagesize}}} \ne \none}} \\
  \writable{\memory} &\equiv \set{\build{i}{\memory_\ramSUBaccess\subb{\floor{\nicefrac{i}{\Cpvmpagesize}}} = \text{W} }}
\end{aligned}$$

We define two sets of indices for the RAM $\memory$: $\readable{\memory}$ is the set of indices which may be read from; and $\writable{\memory}$ is the set of indices which may be written to.

Invocation of the PVM has an exit-reason as the first item in the resultant tuple. It is either:

- Regular program termination caused by an explicit halt instruction, $\halt$.

- Irregular program termination caused by some exceptional circumstance, $\panic$.

- Exhaustion of gas, $\oog$.

- A page fault (attempt to access some address in RAM which is not accessible), $\fault$. This includes the address of the page at fault.

- An attempt at progressing a host-call, $\host$. This allows for the progression and integration of a context-dependent state-machine beyond the regular PVM.

The full definition follows in appendix 23.

## Epochs and Slots

Unlike the *YP* Ethereum with its proof-of-work consensus system, defines a proof-of-authority consensus mechanism, with the authorized validators presumed to be identified by a set of public keys and decided by a *staking* mechanism residing within some system hosted by . The staking system is out of scope for the present work; instead there is an API which may be utilized to update these keys, and we presume that whatever logic is needed for the staking system will be introduced and utilize this API as needed.

The Safrole mechanism subdivides time following genesis into fixed length *epoch*s with each epoch divided into $\Cepochlen = 600$ time*slot*s each of uniform length $\Cslotseconds = 6$ seconds, given an epoch period of $\Cepochlen\cdot\Cslotseconds = 3600$ seconds or one hour.

This six-second slot period represents the minimum time between blocks, and through Safrole we aim to strictly minimize forks arising both due to contention within a slot (where two valid blocks may be produced within the same six-second period) and due to contention over multiple slots (where two valid blocks are produced in different time slots but with the same parent).

Formally when identifying a timeslot index, we use a natural less than $2^{32}$ (in compute parlance, a 32-bit unsigned integer) indicating the number of six-second timeslots from the Common Era. For use in this context we introduce the set $\timeslot$: $$\begin{aligned}
\label{eq:time}
  \timeslot \equiv \Nbits{32}
\end{aligned}$$

This implies that the lifespan of the proposed protocol takes us to mid-August of the year 2840, which with the current course that humanity is on should be ample.

## The Core Model and Services

Whereas in the Ethereum Yellow Paper when defining the state machine which is held in consensus amongst all network participants, we presume that all machines maintaining the full network state and contributing to its enlargement—or, at least, hoping to—evaluate all computation. This “everybody does everything” approach might be called the *on-chain consensus model*. It is unfortunately not scalable, since the network can only process as much logic in consensus that it could hope any individual node is capable of doing itself within any given period of time.

### In-core Consensus

In the present work, we achieve scalability of the work done through introducing a second model for such computation which we call the *in-core consensus model*. In this model, and under normal circumstances, only a subset of the network is responsible for actually executing any given computation and assuring the availability of any input data it relies upon to others. By doing this and assuming a certain amount of computational parallelism within the validator nodes of the network, we are able to scale the amount of computation done in consensus commensurate with the size of the network, and not with the computational power of any single machine. In the present work we expect the network to be able to do upwards of 300 times the amount of computation *in-core* as that which could be performed by a single machine running the virtual machine at full speed.

Since in-core consensus is not evaluated or verified by all nodes on the network, we must find other ways to become adequately confident that the results of the computation are correct, and any data used in determining this is available for a practical period of time. We do this through a crypto-economic game of three stages called *guaranteeing*, *assuring*, *auditing* and, potentially, *judging*. Respectively, these attach a substantial economic cost to the invalidity of some proposed computation; then a sufficient degree of confidence that the inputs of the computation will be available for some period of time; and finally, a sufficient degree of confidence that the validity of the computation (and thus enforcement of the first guarantee) will be checked by some party who we can expect to be honest.

All execution done in-core must be reproducible by any node synchronized to the portion of the chain which has been finalized. Execution done in-core is therefore designed to be as stateless as possible. The requirements for doing it include only the refinement code of the service, the code of the authorizer and any preimage lookups it carried out during its execution.

When a work-report is presented on-chain, a specific block known as the *lookup-anchor* is identified. Correct behavior requires that this must be in the finalized chain and reasonably recent, both properties which may be proven and thus are acceptable for use within a consensus protocol.

We describe this pipeline in detail in the relevant sections later.

### On Services and Accounts

In *YP* Ethereum, we have two kinds of accounts: *contract accounts* (whose actions are defined deterministically based on the account’s associated code and state) and *simple accounts* which act as gateways for data to arrive into the world state and are controlled by knowledge of some secret key. In , all accounts are *service accounts*. Like Ethereum’s contract accounts, they have an associated balance, some code and state. Since they are not controlled by a secret key, they do not need a nonce.

The question then arises: how can external data be fed into the world state of ? And, by extension, how does overall payment happen if not by deducting the account balances of those who sign transactions? The answer to the first lies in the fact that our service definition actually includes *multiple* code entry-points, one concerning *refinement* and the other concerning *accumulation*. The former acts as a sort of high-performance stateless processor, able to accept arbitrary input data and distill it into some much smaller amount of output data, which together with some metadata is known as a *digest*. The latter code is more stateful, providing access to certain on-chain functionality including the possibility of transferring balance and invoking the execution of code in other services. Being stateful this might be said to more closely correspond to the code of an Ethereum contract account.

To understand how breaks up its service code is to understand ’s fundamental proposition of generality and scalability. All data extrinsic to is fed into the refinement code of some service. This code is not executed *on-chain* but rather is said to be executed *in-core*. Thus, whereas the accumulator code is subject to the same scalability constraints as Ethereum’s contract accounts, refinement code is executed off-chain and subject to no such constraints, enabling services to scale dramatically both in the size of their inputs and in the complexity of their computation.

While refinement and accumulation take place in consensus environments of a different nature, both are executed by the members of the same validator set. The protocol through its rewards and penalties ensures that code executed *in-core* has a comparable level of crypto-economic security to that executed *on-chain*, leaving the primary difference between them one of scalability versus synchroneity.

As for managing payment, introduces a new abstraction mechanism based around Polkadot’s Agile Coretime. Within the Ethereum transactive model, the mechanism of account authorization is somewhat combined with the mechanism of purchasing blockspace, both relying on a cryptographic signature to identify a single “transactor” account. In , these are separated and there is no such concept of a “transactor”.

In place of Ethereum’s gas model for purchasing and measuring blockspace, has the concept of *coretime*, which is prepurchased and assigned to an authorization agent. Coretime is analogous to gas insofar as it is the underlying resource which is being consumed when utilizing . Its procurement is out of scope in the present work and is expected to be managed by a system parachain operating within a parachains service itself blessed with a number of cores for running such system services. The authorization agent allows external actors to provide input to a service without necessarily needing to identify themselves as with Ethereum’s transaction signatures. They are discussed in detail in section 8.

# The Header

We must first define the header in terms of its components. The header comprises a parent hash and prior state root ($\H_\SUBparent$ and $\H_\SUBpriorstateroot$), an extrinsic hash $\H_\SUBextrinsichash$, a time-slot index $\H_\SUBtimeslot$, the epoch, winning-tickets and offenders markers $\H_\SUBepochmark$, $\H_\SUBwinnersmark$ and $\H_\SUBoffendersmark$, a block author index $\H_\SUBauthorindex$ and two Bandersnatch signatures; the entropy-yielding VRF signature $\H_\SUBvrfsig$ and a block seal $\H_\SUBsealsig$. Headers may be serialized to an octet sequence with and without the latter seal component using $\fnencode$ and $\fnencodeunsignedheader$ respectively. Formally: $$\label{eq:header}
  \theheader \equiv \tup{\H_\SUBparent, \H_\SUBpriorstateroot, \H_\SUBextrinsichash, \H_\SUBtimeslot, \H_\SUBepochmark, \H_\SUBwinnersmark, \H_\SUBoffendersmark, \H_\SUBauthorindex, \H_\SUBvrfsig, \H_\SUBsealsig}$$

The blockchain is a sequence of blocks, each cryptographically referencing some prior block by including a hash derived from the parent’s header, all the way back to some first block which references the genesis header. We already presume consensus over this genesis header $\genesisheader$ and the state it represents defined as $\genesisstate$.

Excepting the Genesis header, all block headers $\header$ have an associated parent header, whose hash is $\header_\SUBparent$. We denote the parent header $\parentheader{\header} = P\left(\header\right)$: $$\header_\SUBparent \in \hash \,,\quad \H_\SUBparent \equiv \blake{\encode{P\left(\header\right)}}$$

$P$ is thus defined as being the mapping from one block header to its parent block header. With $P$, we are able to define the set of ancestor headers $\ancestors$: $$\begin{aligned}
\label{eq:ancestors}
  h \in \ancestors \Leftrightarrow h = \header \vee (\exists i \in \ancestors : h = P\left(i\right))
\end{aligned}$$

We only require implementations to store headers of ancestors which were authored in the previous $\Cmaxlookupanchorage = 24$ hours of any block $\block$ they wish to validate.

The extrinsic hash is a Merkle commitment to the block’s extrinsic data, taking care to allow for the possibility of reports to individually have their inclusion proven. Given any block $\block = \tup{\header, \extrinsic}$, then formally: $$\begin{aligned}
  \H_\SUBextrinsichash &\in \hash \ ,\quad
  \H_\SUBextrinsichash \equiv \blake{\encode{\blakemany{\mathbf{a}}}} \\
  \where \mathbf{a} &= \sq{
    \encodetickets{\xttickets},
    \encodepreimages{\xtpreimages},
    \mathbf{g},
    \encodeassurances{\xtassurances},
    \encodedisputes{\xtdisputes}
  } \\
  \also \mathbf{g} &= \encode{\var{\sq{\build{
    \tup{\blake{\xgSUBworkreport}, \encode[4]{\xgSUBtimeslot}, \var{\xgSUBcredential}}
  }{
    \tup{\xgSUBworkreport, \xgSUBtimeslot, \xgSUBcredential} \orderedin \xtguarantees
  }}}}
\end{aligned}$$

A block may only be regarded as valid once the time-slot index $\H_\SUBtimeslot$ is in the past. It is always strictly greater than that of its parent. Formally: $$\H_\SUBtimeslot \in \timeslot \,,\quad
  P\left(\H\right)_\SUBtimeslot < \H_\SUBtimeslot\ \wedge\ \H_\SUBtimeslot\cdot\Cslotseconds \leq \wallclock$$

Blocks considered invalid by this rule may become valid as $\wallclock$ advances.

The parent state root $\H_\SUBpriorstateroot$ is the root of a Merkle trie composed by the mapping of the *prior* state’s Merkle root, which by definition is also the parent block’s posterior state. This is a departure from both Polkadot and the Yellow Paper’s Ethereum, in both of which a block’s header contains the *posterior* state’s Merkle root. We do this to facilitate the pipelining of block computation and in particular of Merklization. $$\H_\SUBpriorstateroot \in \hash \,,\quad \H_\SUBpriorstateroot \equiv \merklizestate{\thestate}$$

We assume the state-Merklization function $\fnmerklizestate$ is capable of transforming our state $\thestate$ into a 32-octet commitment. See appendix 26 for a full definition of these two functions.

All blocks have an associated public key to identify the author of the block. We identify this as an index into the posterior current validator set $\activeset'$. We denote the Bandersnatch key of the author as $\H_\SUBauthorbskey$ though note that this is merely an equivalence, and is not serialized as part of the header. $$\H_\SUBauthorindex \in \valindex \,,\quad \H_\SUBauthorbskey \equiv \activeset'[\H_\SUBauthorindex]_\vkSUBbs$$

## The Markers

If not $\none$, then the epoch marker specifies key and entropy relevant to the following epoch in case the ticket contest does not complete adequately (a very much unexpected eventuality). Similarly, the winning-tickets marker, if not $\none$, provides the series of 600 slot sealing “tickets” for the next epoch (see the next section). Finally, the offenders marker is the sequence of Ed25519 keys of newly misbehaving validators, to be fully explained in section 10. Formally: $$\H_\SUBepochmark \in \optional{\tuple{\hash, \hash, \sequence[\Cvalcount]{\tuple{\bskey, \edkey}}}}\,,\quad
  \H_\SUBwinnersmark \in \optional{\sequence[\Cepochlen]{\safroleticket}}\,,\quad
  \H_\SUBoffendersmark \in \sequence{\edkey}$$

The terms are fully defined in sections 6.6 and 10.

# Block Production and Chain Growth

As mentioned earlier, is architected around a hybrid consensus mechanism, similar in nature to that of Polkadot’s BABE/GRANDPA hybrid. ’s block production mechanism, termed Safrole after the novel Sassafras production mechanism of which it is a simplified variant, is a stateful system rather more complex than the Nakamoto consensus described in the *YP*.

The chief purpose of a block production consensus mechanism is to limit the rate at which new blocks may be authored and, ideally, preclude the possibility of “forks”: multiple blocks with equal numbers of ancestors.

To achieve this, Safrole limits the possible author of any block within any given six-second timeslot to a single key-holder from within a prespecified set of *validators*. Furthermore, under normal operation, the identity of the key-holder of any future timeslot will have a very high degree of anonymity. As a side effect of its operation, we can generate a high-quality pool of entropy which may be used by other parts of the protocol and is accessible to services running on it.

Because of its tightly scoped role, the core of Safrole’s state, $\safrole$, is independent of the rest of the protocol. It interacts with other portions of the protocol through $\stagingset$ and $\activeset$, the prospective and active sets of validator keys respectively; $\thetime$, the most recent block’s timeslot; and $\entropy$, the entropy accumulator.

The Safrole protocol generates, once per epoch, a sequence of $\Cepochlen$ *sealing keys*, one for each potential block within a whole epoch. Each block header includes its timeslot index $\H_\SUBtimeslot$ (the number of six-second periods since the Common Era began) and a valid seal signature $\H_\SUBsealsig$, signed by the sealing key corresponding to the timeslot within the aforementioned sequence. Each sealing key is in fact a pseudonym for some validator which was agreed the privilege of authoring a block in the corresponding timeslot.

In order to generate this sequence of sealing keys in regular operation, and in particular to do so without making public the correspondence relation between them and the validator set, we use a novel cryptographic structure known as a RingVRF, utilizing the Bandersnatch curve. Bandersnatch RingVRF allows for a proof to be provided which simultaneously guarantees the author controlled a key within a set (in our case validators), and secondly provides an output, an unbiasable deterministic hash giving us a secure verifiable random function (VRF). This anonymous and secure random output is a *ticket* and validators’ tickets with the best score define the new sealing keys allowing the chosen validators to exercise their privilege and create a new block at the appropriate time.

## Timekeeping

Here, $\thetime$ defines the most recent block’s slot index, which we transition to the slot index as defined in the block’s header: $$\label{eq:timeslotindex}
  \thetime \in \timeslot \ ,\quad
  \thetime' \equiv \H_\SUBtimeslot$$

We track the slot index in state as $\thetime$ in order that we are able to easily both identify a new epoch and determine the slot at which the prior block was authored. We denote $e$ as the prior’s epoch index and $m$ as the prior’s slot phase index within that epoch and $e'$ and $m'$ are the corresponding values for the present block: $$\begin{aligned}
  \mathrm{let}\quad e \remainder m = \frac{\thetime}{\Cepochlen} \,,\quad
  e' \remainder m' = \frac{\thetime'}{\Cepochlen}
\end{aligned}$$

## Safrole Basic State

We restate $\safrole$ into a number of components: $$\begin{aligned}
  \label{eq:consensusstatecomposition}
  \safrole &\equiv \tuple{
    \pendingset,\,
    \epochroot,\,
    \sealtickets,\,
    \ticketaccumulator
  }
\end{aligned}$$

$\epochroot$ is the epoch’s root, a Bandersnatch ring root composed with the one Bandersnatch key of each of the next epoch’s validators, defined in $\pendingset$ (itself defined in the next section). $$\begin{aligned}
  \label{eq:epochrootspec}
  \epochroot &\in \ringroot
\end{aligned}$$

Finally, $\ticketaccumulator$ is the ticket accumulator, a series of highest-scoring ticket identifiers to be used for the next epoch. $\sealtickets$ is the current epoch’s slot-sealer series, which is either a full complement of $\Cepochlen$ tickets or, in the case of a fallback mode, a series of $\Cepochlen$ Bandersnatch keys: $$\begin{aligned}
  \label{eq:ticketaccumulatorsealticketsspec}
  \ticketaccumulator \in \sequence[:\Cepochlen]{\safroleticket} \,,\quad
  \sealtickets \in \sequence[\Cepochlen]{\safroleticket} \cup \sequence[\Cepochlen]{\bskey}
\end{aligned}$$

Here, $\safroleticket$ is used to denote the set of *tickets*, a combination of a verifiably random ticket identifier $\stSUBid$ and the ticket’s entry-index $\stSUBentryindex$: $$\begin{aligned}
  \label{eq:ticket}
  \safroleticket &\equiv \tuple{
    \isa{\stSUBid}{\hash},\,
    \isa{\stSUBentryindex}{\ticketentryindex}
  }
\end{aligned}$$

As we state in section 6.4, Safrole requires that every block header $\H$ contain a valid seal $\H_\SUBsealsig$, which is a Bandersnatch signature for a public key at the appropriate index $m$ of the current epoch’s seal-key series, present in state as $\sealtickets$.

## Key Rotation

In addition to the active set of validator keys $\activeset$ and staging set $\stagingset$, internal to the Safrole state we retain a pending set $\pendingset$. The active set is the set of keys identifying the nodes which are currently privileged to author blocks and carry out the validation processes, whereas the pending set $\pendingset$, which is reset to $\stagingset$ at the beginning of each epoch, is the set of keys which will be active in the next epoch and which determine the Bandersnatch ring root which authorizes tickets into the sealing-key contest for the next epoch. $$\begin{aligned}
  \label{eq:validatorkeys}
  \stagingset \in \allvalkeys \;,\quad
  \pendingset \in \allvalkeys \;,\quad
  \activeset \in \allvalkeys \;,\quad
  \previousset \in \allvalkeys
\end{aligned}$$

We must introduce $\valkey$, the set of validator key tuples. This is a combination of a set of cryptographic public keys and metadata which is an opaque octet sequence, but utilized to specify practical identifiers for the validator, not least a hardware address.

The set of validator keys itself is equivalent to the set of 336-octet sequences. However, for clarity, we divide the sequence into four easily denoted components. For any validator key $k$, the Bandersnatch key is denoted $k_\vkSUBbs$, and is equivalent to the first 32-octets; the Ed25519 key, $k_\vkSUBed$, is the second 32 octets; the BLS key denoted $k_\vkSUBbls$ is equivalent to the following 144 octets, and finally the metadata $k_\vkSUBmetadata$ is the last 128 octets. Formally: $$\begin{aligned}
  \valkey &\equiv \blob[336] \\
  \forall \vkX \in \valkey : \vkX_\vkSUBbs \in \bskey &\equiv \vkX\subrange{0}{32} \\
  \forall \vkX \in \valkey : \vkX_\vkSUBed \in \edkey &\equiv \vkX\subrange{32}{32} \\
  \forall \vkX \in \valkey : \vkX_\vkSUBbls \in \blskey &\equiv \vkX\subrange{64}{144} \\
  \forall \vkX \in \valkey : \vkX_\vkSUBmetadata \in \metadatakey &\equiv \vkX\subrange{208}{128}
\end{aligned}$$

With a new epoch under regular conditions, validator keys get rotated and the epoch’s Bandersnatch key root is updated into $\epochroot'$: $$\begin{aligned}
  \tup{\pendingset', \activeset', \previousset', \epochroot'} &\equiv \begin{cases}
    (\Phi(\stagingset), \pendingset, \activeset, z) &\when e' > e \\ \tup{\pendingset, \activeset, \previousset, \epochroot} &\otherwise
  \end{cases} \\
  \nonumber \where z &= \getringroot{\sq{\build{k_\vkSUBbs}{k \orderedin \pendingset'}}} \\
  \label{eq:blacklistfilter} \Phi(\mathbf{k}) &\equiv \sq{
    \build{
      \begin{rcases}
        \sq{0, 0, \dots} &\when \vkX_\vkSUBed \in \offenders' \\
        \vkX &\otherwise
      \end{rcases}
    }{
      \vkX \orderedin \mathbf{k}
    }
  }
\end{aligned}$$

Note that on epoch changes the posterior queued validator key set $\pendingset'$ is defined such that incoming keys belonging to the offenders $\offenders'$ are replaced with a null key containing only zeroes. The origin of the offenders is explained in section 10.

## Sealing and Entropy Accumulation

The header must contain a valid seal and valid VRF output. These are two signatures both using the current slot’s seal key; the message data of the former is the header’s serialization omitting the seal component $\H_\SUBsealsig$, whereas the latter is used as a bias-resistant entropy source and thus its message must already have been fixed: we use the entropy stemming from the VRF of the seal signature. Formally: $$\begin{aligned}
  \nonumber \using i = \cyclic{\sealtickets'[\H_\SUBtimeslot]}\colon \\
  \label{eq:ticketconditiontrue}
  \sealtickets' \in \sequence{\safroleticket} &\implies \abracegroup[\,]{
      &i_\stSUBid = \banderout{\H_\SUBsealsig}\,,\\
      &\H_\SUBsealsig \in \bssignature{\H_\SUBauthorbskey}{\Xticket \concat \entropy'_3 \append i_\stSUBentryindex}{\encodeunsignedheader{\H}}\,,\\
      &\isticketed = 1
  }\\
  \label{eq:ticketconditionfalse}
  \sealtickets' \in \sequence{\bskey} &\implies \abracegroup[\,]{
      &i = \H_\SUBauthorbskey\,,\\
      &\H_\SUBsealsig \in \bssignature{\H_\SUBauthorbskey}{\Xfallback \concat \entropy'_3}{\encodeunsignedheader{\H}}\,,\\
      &\isticketed = 0
  }\\
  \label{eq:vrfsigcheck}
  \H_\SUBvrfsig &\in \bssignature{\H_\SUBauthorbskey}{\Xentropy \concat \banderout{\H_\SUBsealsig}}{\sq{}} \\
  \Xentropy &= \token{\$jam\_entropy}\\
  \Xfallback &= \token{\$jam\_fallback\_seal}\\
  \Xticket &= \token{\$jam\_ticket\_seal}
  
\end{aligned}$$

Sealing using the ticket is of greater security, and we utilize this knowledge when determining a candidate block on which to extend the chain, detailed in section 19. We thus note that the block was sealed under the regular security with the boolean marker $\isticketed$. We define this only for the purpose of ease of later specification.

In addition to the entropy accumulator $\entropyaccumulator$, we retain three additional historical values of the accumulator at the point of each of the three most recently ended epochs, $\entropy_1$, $\entropy_2$ and $\entropy_3$. The second-oldest of these $\entropy_2$ is utilized to help ensure future entropy is unbiased (see equation eq:ticketsextrinsic) and seed the fallback seal-key generation function with randomness (see equation eq:slotkeysequence). The oldest is used to regenerate this randomness when verifying the seal above (see equations eq:ticketconditionfalse and eq:ticketconditiontrue). $$\begin{aligned}
  \label{eq:entropycomposition}
  \entropy &\in \sequence[4]{\hash}
\end{aligned}$$

$\entropyaccumulator$ defines the state of the randomness accumulator to which the provably random output of the VRF, the signature over some unbiasable input, is combined each block. $\entropy_1$, $\entropy_2$ and $\entropy_3$ meanwhile retain the state of this accumulator at the end of the three most recently ended epochs in order. $$\begin{aligned}
  \entropyaccumulator' &\equiv \blake{\entropyaccumulator \concat \banderout{\H_\SUBvrfsig}}
\end{aligned}$$

On an epoch transition (identified as the condition $e' > e$), we therefore rotate the accumulator value into the history $\entropy_1$, $\entropy_2$ and $\entropy_3$: $$\begin{aligned}
  \tup{\entropy'_1, \entropy'_2, \entropy'_3} &\equiv \begin{cases}
    \tup{\entropy_0, \entropy_1, \entropy_2} &\when e' > e \\
    \tup{\entropy_1, \entropy_2, \entropy_3} &\otherwise
  \end{cases}
\end{aligned}$$

## The Slot Key Sequence

The posterior slot key sequence $\safroleticket$ is one of three expressions depending on the circumstance of the block. If the block is not the first in an epoch, then it remains unchanged from the prior $\sealtickets$. If the block signals the next epoch (by epoch index) and the previous block’s slot was within the closing period of the previous epoch, then it takes the value of the prior ticket accumulator $\ticketaccumulator$. Otherwise, it takes the value of the fallback key sequence. Formally: $$\begin{aligned}
  \label{eq:slotkeysequence}
  \sealtickets' &\equiv \begin{cases}
    Z(\ticketaccumulator) &\when e' = e + 1 \wedge m \geq \Cepochtailstart \wedge \len{\ticketaccumulator} = \Cepochlen\!\!\\
    \sealtickets &\when e' = e \\
    F(\entropy'_2, \activeset') \!\!\!&\otherwise
  \end{cases}
\end{aligned}$$

Here, we use $Z$ as the outside-in sequencer function, defined as follows: $$Z\colon\abracegroup[\,]{
    \sequence[\Cepochlen]{\safroleticket} &\to \sequence[\Cepochlen]{\safroleticket}\\
    \mathbf{s} &\mapsto \sq{\mathbf{s}_0, \mathbf{s}_{\len{\mathbf{s}} - 1}, \mathbf{s}_1, \mathbf{s}_{\len{\mathbf{s}} - 2}, \dots}\\
  }$$

Finally, $F$ is the fallback key sequence function which selects an epoch’s worth of validator Bandersnatch keys ($\sequence[\Cepochlen]{\bskey}$) from the validator key set $\mathbf{k}$ using the entropy collected on-chain $r$: $$\label{eq:fallbackkeysequence}
  F\colon \abracegroup[\ ]{
    \tuple{\hash,\,\sequence{\valkey}} &\to \sequence[\Cepochlen]{\bskey}\\
    \tup{r,\, \mathbf{k}} &\mapsto \sq{\build{
      \cyclic{\mathbf{k}\sub{\decode[4]{\blake{r \concat \encode[4]{i}}_{\dots 4}}}}_\vkSUBbs
    }{
      i \in \epochindex
    }}
  }\!\!\!$$

## The Markers

The epoch and winning-tickets markers are information placed in the header in order to minimize data transfer necessary to determine the validator keys associated with any given epoch. They are particularly useful to nodes which do not synchronize the entire state for any given block since they facilitate the secure tracking of changes to the validator key sets using only the chain of headers.

As mentioned earlier, the header’s epoch marker $\H_\SUBepochmark$ is either empty or, if the block is the first in a new epoch, then a tuple of the next and current epoch randomness, along with a sequence of tuples containing both Bandersnatch keys and Ed25519 keys for each validator defining the validator keys beginning in the next epoch. Formally: $$\begin{aligned}
  \label{eq:epochmarker}
  \H_\SUBepochmark &\equiv \begin{cases}
    \tup{ \entropyaccumulator, \entropy_1, \sq{\build{
      \tup{k_\vkSUBbs, k_\vkSUBed}
    }{
      k \orderedin \pendingset'
    }} } \qquad\qquad &\when e' > e \\
    \none & \otherwise
  \end{cases}
\end{aligned}$$

The winning-tickets marker $\H_\SUBwinnersmark$ is either empty or, if the block is the first after the end of the submission period for tickets and if the ticket accumulator is saturated, then the final sequence of ticket identifiers. Formally: $$\begin{aligned}
  \label{eq:winningticketsmarker}
  \H_\SUBwinnersmark &\equiv \begin{cases}
    Z(\ticketaccumulator) &\when e' = e \wedge m < \Cepochtailstart \le m' \wedge \len{\ticketaccumulator} = \Cepochlen \\
    \none & \otherwise
  \end{cases}
\end{aligned}$$

## The Extrinsic and Tickets

The extrinsic $\xttickets$ is a sequence of proofs of valid tickets; a ticket implies an entry in our epochal “contest” to determine which validators are privileged to author a block for each timeslot in the following epoch. Tickets specify an entry index together with a proof of ticket’s validity. The proof implies a ticket identifier, a high-entropy unbiasable 32-octet sequence, which is used both as a score in the aforementioned contest and as input to the on-chain VRF.

Towards the end of the epoch ($\Cepochtailstart$ slots from the start) this contest is closed implying successive blocks within the same epoch must have an empty tickets extrinsic. At this point, the following epoch’s seal key sequence becomes fixed.

We define the extrinsic as a sequence of proofs of valid tickets, each of which is a tuple of an entry index (a natural number less than $\Cticketentries$) and a proof of ticket validity. Formally: $$\begin{aligned}
  \label{eq:ticketsextrinsic}
  \xttickets &\in \sequence{\tuple{
    \isa{\xtSUBentryindex}{\Nmax{\Cticketentries}},\,
    \isa{\xtSUBproof}{\bsringproof{\epochroot'}{\Xticket \concat \entropy'_2 \append \xtSUBentryindex}{\sq{}}}
  }} \\
  \label{eq:enforceticketlimit}
  \len{\xttickets} &\le \begin{cases}
      \Cmaxblocktickets &\when m' < \Cepochtailstart \\
      0 &\otherwise
  \end{cases}
\end{aligned}$$

We define $\mathbf{n}$ as the set of new tickets, with the ticket identifier, a hash, defined as the output component of the Bandersnatch RingVRF proof: $$\begin{aligned}
  \mathbf{n} &\equiv \sq{\build{
    \tup{
      \is{\stSUBid}{\banderout{i_\xtSUBproof}},\,
      \is{\stSUBentryindex}{i_\stSUBentryindex}
    }
  }{
    i \orderedin \xttickets
  }}
\end{aligned}$$

The tickets submitted via the extrinsic must already have been placed in order of their implied identifier. Duplicate identifiers are never allowed lest a validator submit the same ticket multiple times: $$\begin{aligned}
  \mathbf{n} &= \sqorderuniqby{x_\stSUBid}{x \in \mathbf{n}} \\
  \set{ \build{ x_\stSUBid }{ x \in \mathbf{n} }} &\disjoint \set{ \build { x_\stSUBid }{ x \in \ticketaccumulator }}
\end{aligned}$$

The new ticket accumulator $\ticketaccumulator'$ is constructed by merging new tickets into the previous accumulator value (or the empty sequence if it is a new epoch): $$\begin{aligned}
    \ticketaccumulator' &\equiv  {\overrightarrow{\sqorderby{x_\stSUBid}{x \in \mathbf{n} \cup \begin{cases} \none\ &\when e' > e \\ \ticketaccumulator\ &\otherwise \end{cases}}~}}^\Cepochlen \\
  \end{aligned}$$

The maximum size of the ticket accumulator is $\Cepochlen$. On each block, the accumulator becomes the lowest items of the sorted union of tickets from prior accumulator $\ticketaccumulator$ and the submitted tickets. It is invalid to include useless tickets in the extrinsic, so all submitted tickets must exist in their posterior ticket accumulator. Formally: $$\begin{aligned}
  \mathbf{n} \subseteq \ticketaccumulator'
\end{aligned}$$

Note that it can be shown that in the case of an empty extrinsic $\xttickets = \sq{}$, as implied by $m' \ge \Cepochtailstart$, and unchanged epoch ($e' = e$), then $\ticketaccumulator' = \ticketaccumulator$.

# Recent History

We retain in state information on the most recent $\Crecenthistorylen$ blocks. This is used to preclude the possibility of duplicate or out of date work-reports from being submitted. $$\begin{aligned}
  \label{eq:recentspec}
  \recent &\equiv \tup{\recenthistory, \accoutbelt}\\
  \label{eq:recenthistoryspec}
  \recenthistory &\in \sequence[:\Crecenthistorylen]{\tuple{
    \isa{\rhSUBheaderhash}{\hash},
    \isa{\rhSUBstateroot}{\hash},
    \isa{\rhSUBaccoutlogsuperpeak}{\hash},
    \isa{\rhSUBreportedpackagehashes}{\dictionary{\hash}{\hash}}
  }}\\
  \label{eq:accoutbeltspec}
  \accoutbelt &\in \sequence{\optional{\hash}} \\
  \label{eq:lastaccoutspec}
  \lastaccout &\in \sequence{\tup{\serviceid, \hash}}
\end{aligned}$$

For each recent block, we retain its header hash, its state root, its accumulation-result MMB and the corresponding work-package hashes of each item reported (which is no more than the total number of cores, $\Ccorecount = 341$).

During the accumulation stage, a value with the partial transition of this state is provided which contains the correction for the newly-known state-root of the parent block: $$\label{eq:correctlaststateroot}
  \recenthistorypostparentstaterootupdate \equiv \recenthistory\quad\exc\quad\recenthistorypostparentstaterootupdate\subb{\len{\recenthistory} - 1}_\rhSUBstateroot = \H_\SUBpriorstateroot$$

We define the new Accumulation Output Log $\accoutbelt$. This is formed from the block’s accumulation-output sequence $\lastaccout'$ (defined in section 12), taking its root using the basic binary Merklization function ($\fnmerklizewb$, defined in appendix 27) and appending it to the previous log value with the MMB append function (defined in appendix 27.2). Throughout, the Keccak hash function is used to maximize compatibility with legacy systems: $$\begin{aligned}
  \using \mathbf{s} &= \sq{\build{\encode[4]{s} \concat \encode{h}}{\tup{s, h} \orderedin \lastaccout'}}\\
  \label{eq:accoutbeltdef}
  \accoutbelt' &\equiv \mmrappend{\accoutbelt, \merklizewb{\mathbf{s}, \fnkeccak}, \fnkeccak}
\end{aligned}$$

The final state transition for $\recenthistory$ appends a new item including the new block’s header hash, a Merkle commitment to the block’s Accumulation Output Log and the set of work-reports made into it (for which we use the guarantees extrinsic, $\xtguarantees$). Formally: $$\label{eq:recenthistorydef}
  \begin{aligned}
    \recenthistory' &\equiv {\overleftarrow{\recenthistorypostparentstaterootupdate \append \tup{
      \rhSUBreportedpackagehashes,
      \is{\rhSUBheaderhash}{\blake{\theheader}},
      \is{\rhSUBstateroot}{\zerohash},
      \is{\rhSUBaccoutlogsuperpeak}{\mmrsuperpeak{\accoutbelt'}}
      }}}^\Crecenthistorylen \\
    \where \rhSUBreportedpackagehashes &= \set{\build{
        \kv{
          ((g_\xgSUBworkreport)_\wrSUBavspec)_\asSUBpackagehash
        }{
          ((g_\xgSUBworkreport)_\wrSUBavspec)_\asSUBsegroot
        }
      }{
        g \in \xtguarantees
      }}
  \end{aligned}$$

The new state-trie root is the zero hash, $\zerohash$, which is inaccurate but safe since $\recent'$ is not utilized except to define the next block’s $\recentpostparentstaterootupdate$, which contains a corrected value for this, as per equation eq:correctlaststateroot.

# Authorization

We have previously discussed the model of work-packages and services in section 4.9, however we have yet to make a substantial discussion of exactly how some *coretime* resource may be apportioned to some work-package and its associated service. In the *YP* Ethereum model, the underlying resource, gas, is procured at the point of introduction on-chain and the purchaser is always the same agent who authors the data which describes the work to be done (the transaction). Conversely, in Polkadot the underlying resource, a parachain slot, is procured with a substantial deposit for typically 24 months at a time and the procurer, generally a parachain team, will often have no direct relation to the author of the work to be done (a parachain block).

On a principle of flexibility, we would wish capable of supporting a range of interaction patterns both Ethereum-style and Polkadot-style. In an effort to do so, we introduce the *authorization system*, a means of disentangling the intention of usage for some coretime from the specification and submission of a particular workload to be executed on it. We are thus able to disassociate the purchase and assignment of coretime from the specific determination of work to be done with it, and so are able to support both Ethereum-style and Polkadot-style interaction patterns.

## Authorizers and Authorizations

The authorization system involves three key concepts: *Authorizers*, *Tokens* and *Traces*. A Token is simply a piece of opaque data to be included with a work-package to help make an argument that the work-package should be authorized. Similarly, a Trace is a piece of opaque data which helps characterize or describe some successful authorization. An Authorizer meanwhile, is a piece of logic which executes within some pre-specified and well-known computational limits and determines whether a work-package—including its Token—is authorized for execution on some particular core and yields a Trace on success.

Authorizers are identified as the hash of their PVM code concatenated with their Configuration blob, the latter being, like Tokens and Traces, opaque data meaningful to the PVM code. The process by which work-packages are determined to be authorized (or not) is not the competence of on-chain logic and happens entirely in-core and as such is discussed in section 14.3. However, on-chain logic must identify each set of authorizers assigned to each core in order to verify that a work-package is legitimately able to utilize that resource. It is this subsystem we will now define.

## Pool and Queue

We define the set of authorizers allowable for a particular core $\SUBcore$ as the *authorizer pool* $\authpool[\SUBcore]$. To maintain this value, a further portion of state is tracked for each core: the core’s current *authorizer queue* $\authqueue[\SUBcore]$, from which we draw values to fill the pool. Formally: $$\label{eq:authstatecomposition}
  \authpool \in \sequence[\Ccorecount]{\sequence[:\Cauthpoolsize]{\hash}}\ , \qquad
  \authqueue \in \sequence[\Ccorecount]{\sequence[\Cauthqueuesize]{\hash}}$$

Note: The portion of state $\authqueue$ may be altered only through an exogenous call made from the accumulate logic of an appropriately privileged service.

The state transition of a block involves placing a new authorization into the pool from the queue: $$\begin{aligned}
  &\forall \SUBcore \in \coreindex : \authpool'\subb{\SUBcore} \equiv {\overleftarrow{F(\SUBcore) \append \cyclic{\authqueue'\subb{\SUBcore}\subb{\H_\SUBtimeslot}}}}^{\Cauthpoolsize} \\
  &F(\SUBcore) \equiv \begin{cases} \authpool[\SUBcore] \seqminusl \set{(g_\xgSUBworkreport)_\wrSUBauthorizer} &\when \exists g \in \xtguarantees : (g_\xgSUBworkreport)_\SUBcore = \SUBcore \\ \authpool[\SUBcore] & \otherwise \end{cases}
\end{aligned}$$

Since $\authpool'$ is dependent on $\authqueue'$, practically speaking, this step must be computed after accumulation, the stage in which $\authqueue'$ is defined. Note that we utilize the guarantees extrinsic $\xtguarantees$ to remove the oldest authorizer which has been used to justify a guaranteed work-package in the current block. This is further defined in equation eq:guaranteesextrinsic.

# Service Accounts

As we already noted, a service in is somewhat analogous to a smart contract in Ethereum in that it includes amongst other items, a code component, a storage component and a balance. Unlike Ethereum, the code is split over two isolated entry-points each with their own environmental conditions; one, *Refinement*, is essentially stateless and happens in-core, and the other, *Accumulation*, which is stateful and happens on-chain. It is the latter which we will concern ourselves with now.

Service accounts are held in state under $\accounts$, a partial mapping from a service identifier $\serviceid$ into a tuple of named elements which specify the attributes of the service relevant to the protocol. Formally: $$\begin{aligned}
\label{eq:serviceaccounts}
  \serviceid &\equiv \Nbits{32} \\
  \accounts &\in \dictionary{\serviceid}{\serviceaccount}
\end{aligned}$$

The service account is defined as the tuple of storage dictionary $\saSUBstorage$, preimage lookup dictionaries $\saSUBpreimages$ and $\saSUBrequests$, code hash $\saSUBcodehash$, balance $\saSUBbalance$ and gratis storage offset $\saSUBgratis$, as well as the two code gas limits $\saSUBminaccgas$ & $\saSUBminmemogas$. We also record certain usage characteristics concerning the account: the time slot at creation $\saSUBcreated$, the time slot at the most recent accumulation $\saSUBlastacc$ and the parent service $\saSUBparent$. Formally: $$\begin{aligned}
\label{eq:serviceaccount}
  \serviceaccount \equiv \tuple{\ \begin{aligned}
    \saSUBstorage &\in \dictionary{\blob}{\blob}\,,\
    \saSUBpreimages \in \dictionary{\hash}{\blob}\,,\\
    \saSUBrequests &\in \dictionary{\tuple{\hash,\bloblength}}{\sequence[:3]{\timeslot}}\,,\\
    \saSUBgratis &\in \balance\,,\
    \saSUBcodehash \in \hash\,,\
    \saSUBbalance \in \balance\,,\
    \saSUBminaccgas \in \gas\,,\\
    \saSUBminmemogas &\in \gas\,,\
    \saSUBcreated \in \timeslot\,,\
    \saSUBlastacc \in \timeslot\,,\
    \saSUBparent \in \serviceid\\
    %i, o, f
  \end{aligned}\,}
\end{aligned}$$

Thus, the balance of the service of index $s$ would be denoted $\accounts\subb{s}_\saSUBbalance$ and the storage item of key $\mathbf{k} \in \blob$ for that service is written $\accounts\subb{s}_\saSUBstorage\subb{\mathbf{k}}$.

## Code and Gas

The code and associated metadata of a service account is identified by a hash which, if the service is to be functional, must be present within its preimage lookup (see section 9.2) and have a preimage which is a proper encoding of the two blobs. We thus define the actual code $\saSUBcode$ and metadata $\saSUBmetadata$: $$\begin{aligned}
  \forall \mathbf{a} \in \serviceaccount : \tup{\mathbf{a}_\saSUBmetadata, \mathbf{a}_\saSUBcode} \equiv \begin{cases}
    \tup{\mathbf{m}, \mathbf{c}} &\when \encode{\var{\mathbf{m}}, \mathbf{c}} = \mathbf{a}_\saSUBpreimages[\mathbf{a}_\saSUBcodehash] \\
    \tup{\none, \none} &\otherwise
  \end{cases}
\end{aligned}$$

There are two entry-points in the code:

0 `refine`  
Refinement, executed in-core and stateless.[^10]

1 `accumulate`  
Accumulation, executed on-chain and stateful.

Refinement and accumulation are described in more detail in sections 14.4 and 12.2 respectively.

As stated in appendix 23, execution time in the virtual machine is measured deterministically in units of *gas*, represented as a natural number less than $2^{64}$ and formally denoted $\gas$. We may also use $\signedgas$ to denote the set $\Z_{-2^{63}\dots2^{63}}$ if the quantity may be negative. There are two limits specified in the account, which determine the minimum gas required in order to execute the *Accumulate* entry-point of the service’s code. $\saSUBminaccgas$ is the minimum gas required per work-item, while $\saSUBminmemogas$ is the minimum gas required per deferred-transfer.

## Preimage Lookups

In addition to storing data in arbitrary key/value pairs available only on-chain, an account may also solicit data to be made available also in-core, and thus available to the Refine logic of the service’s code. State concerning this facility is held under the service’s $\saSUBpreimages$ and $\saSUBrequests$ components.

There are several differences between preimage-lookups and storage. Firstly, preimage-lookups act as a mapping from a hash to its preimage, whereas general storage maps arbitrary keys to values. Secondly, preimage data is supplied extrinsically, whereas storage data originates as part of the service’s accumulation. Thirdly preimage data, once supplied, may not be removed freely; instead it goes through a process of being marked as unavailable, and only after a period of time may it be removed from state. This ensures that historical information on its existence is retained. The final point especially is important since preimage data is designed to be queried in-core, under the Refine logic of the service’s code, and thus it is important that the historical availability of the preimage is known.

We begin by reformulating the portion of state concerning our data-lookup system. The purpose of this system is to provide a means of storing static data on-chain such that it may later be made available within the execution of any service code as a function accepting only the hash of the data and its length in octets.

During the on-chain execution of the *Accumulate* function, this is trivial to achieve since there is inherently a state which all validators verifying the block necessarily have complete knowledge of, $\thestate$. However, for the in-core execution of *Refine*, there is no such state inherently available to all validators; we thus name a historical state, the *lookup anchor* which must be considered recently finalized before the work’s implications may be accumulated hence providing this guarantee.

By retaining historical information on its availability, we become confident that any validator with a recently finalized view of the chain is able to determine whether any given preimage was available at any time within the period where auditing may occur. This ensures confidence that judgments will be deterministic even without consensus on chain state.

Restated, we must be able to define some *historical* lookup function $\histlookup$ which determines whether the preimage of some hash was available for lookup by some service account at some timeslot, and if so, provide it: $$\begin{aligned}
  \histlookup\colon \abracegroup[\ ]{
    \tuple{\serviceaccount, \Nmax{(\H_\SUBtimeslot - \Cexpungeperiod) \dots \H_\SUBtimeslot}, \hash} &\to \optional{\blob} \\
    (\mathbf{a}, t, \blake{\mathbf{p}}) &\mapsto v : v \in \set{ \mathbf{p}, \none }
  }
\end{aligned}$$

This function is defined shortly below in equation eq:historicallookup.

The preimage lookup for some service of index $s$ is denoted $\accounts\subb{s}_\saSUBpreimages$ is a dictionary mapping a hash to its corresponding preimage. Additionally, there is metadata associated with the lookup denoted $\accounts\subb{s}_\saSUBrequests$ which is a dictionary mapping some hash and presupposed length into historical information.

### Invariants

The state of the lookup system naturally satisfies a number of invariants. Firstly, any preimage value must correspond to its hash, equation eq:preimageconstraints. Secondly, a preimage value being in state implies that its hash and length pair has some associated status, also in equation eq:preimageconstraints. Formally: $$\label{eq:preimageconstraints}
  \forall \mathbf{a} \in \serviceaccount, \kv{h}{\mathbf{d}} \in \mathbf{a}_\saSUBpreimages \Rightarrow
    h = \blake{\mathbf{d}}\wedge
    \tup{h , \len{\mathbf{d}}} \in \keys{\mathbf{a}_\saSUBrequests}$$

### Semantics

The historical status component $h \in \sequence[:3]{\timeslot}$ is a sequence of up to three time slots and the cardinality of this sequence implies one of four modes:

- $h = \sequence{}$: The preimage is *requested*, but has not yet been supplied.

- $h \in \sequence[1]{\timeslot}$: The preimage is *available* and has been from time $h_0$.

- $h \in \sequence[2]{\timeslot}$: The previously available preimage is now *unavailable* since time $h_1$. It had been available from time $h_0$.

- $h \in \sequence[3]{\timeslot}$: The preimage is *available* and has been from time $h_2$. It had previously been available from time $h_0$ until time $h_1$.

The historical lookup function $\histlookup$ may now be defined as: $$\begin{aligned}\label{eq:historicallookup}
    &\histlookup\colon \tuple{\serviceaccount, \timeslot, \hash} \to \optional{\blob} \\
    &\histlookup(\mathbf{a}, t, h) \equiv \begin{cases}
      \mathbf{a}_\saSUBpreimages\subb{h}\!\!\!\! &\when h \in \keys{\mathbf{a}_\saSUBpreimages} \wedge I(\mathbf{a}_\saSUBrequests\subb{h, \len{\mathbf{a}_\saSUBpreimages\subb{h}}}, t) \!\!\!\!\! \\
      \none &\otherwise
    \end{cases}\\
    &\where I(\mathbf{l}, t) = \begin{cases}
      \bot &\when \sq{} = \mathbf{l} \\
      x \le t &\when \sq{x} = \mathbf{l} \\
      x \le t < y &\when \sq{x, y} = \mathbf{l} \\
      x \le t < y \vee z \le t &\when \sq{x, y, z} = \mathbf{l} \\
    \end{cases}
  \end{aligned}$$

## Account Footprint and Threshold Balance

We define the dependent values $\saSUBitems$ and $\saSUBoctets$ as the storage footprint of the service, specifically the number of items in storage and the total number of octets used in storage. They are defined purely in terms of the storage map of a service, and it must be assumed that whenever a service’s storage is changed, these change also.

Furthermore, as we will see in the account serialization function in section 25, these are expected to be found explicitly within the Merklized state data. Because of this we make explicit their set.

We may then define a third dependent term $\saSUBminbalance$, the minimum, or *threshold*, balance needed for any given service account in terms of its storage footprint. $$\begin{aligned}
  \forall \mathbf{a} \in \values{\accounts}\colon \abracegroup{
    \mathbf{a}_\saSUBitems \in \Nbits{32} &\equiv
      2\cdot\len{\,\mathbf{a}_\saSUBrequests\,} + \len{\,\mathbf{a}_\saSUBstorage\,} \\
    \mathbf{a}_\saSUBoctets \in \Nbits{64} &\equiv
      \sum\limits_{\,\tup{h, z} \in \keys{\mathbf{a}_\saSUBrequests}\,} \!\!\!\!81 + z \\
    &\phantom{\equiv\ } + \sum\limits_{\tup{x, y} \in \mathbf{a}_\saSUBstorage} 34 + \len{y} + \len{x} \\
    \label{eq:deposits}
    \mathbf{a}_\saSUBminbalance \in \balance &\equiv
      \max(0,
        \Cbasedeposit
        + \Citemdeposit \cdot \mathbf{a}_\saSUBitems
        + \Cbytedeposit \cdot \mathbf{a}_\saSUBoctets
        - \mathbf{a}_\saSUBgratis
      )
  }
\end{aligned}$$

## Service Privileges

includes the ability to bestow privileges on a number of services. The portion of state in which this is held is denoted $\privileges$ and includes five kinds of privilege. The first, $\manager$, is the index of the *manager* service which is the service able to effect an alteration of $\privileges$ from block to block as well as bestow services with storage deposit credits. The next, $\delegator$, is able to set $\stagingset$. Then $\registrar$ alone is able to create new service accounts with indices in the protected range. The following, $\assigners$, are the service indices capable of altering the authorizer queue $\authqueue$, one for each core.

Finally, $\alwaysaccers$ is a small dictionary containing the indices of services which automatically accumulate in each block together with a basic amount of gas with which each accumulates. Formally: $$\begin{aligned}
  \label{eq:privilegesspec}
  \privileges &\equiv \tuple{
    \manager,
    \delegator,
    \registrar,
    \assigners,
    \alwaysaccers
  }\\
  \manager &\in \serviceid \ ,\qquad
  \delegator \in \serviceid \ ,\qquad
  \registrar \in \serviceid \\
  \assigners &\in \sequence[\Ccorecount]{\serviceid} \ ,\qquad
  \alwaysaccers \in \dictionary{\serviceid}{\gas}
\end{aligned}$$

# Disputes, Verdicts and Judgments

provides a means of recording *judgments*: consequential votes amongst most of the validators over the validity of a *work-report* (a unit of work done within , see section 11). Such collections of judgments are known as *verdicts*. also provides a means of registering *offenses*, judgments and guarantees which dissent with an established *verdict*. Together these form the *disputes* system.

The registration of a verdict is not expected to happen very often in practice, however it is an important security backstop for removing and banning invalid work-reports from the processing pipeline as well as removing troublesome keys from the validator set where there is consensus over their malfunction. It also helps coordinate nodes to revert chain-extensions containing invalid work-reports and provides a convenient means of aggregating all offending validators for punishment in a higher-level system.

Judgement statements come about naturally as part of the auditing process and are expected to be positive, further affirming the guarantors’ assertion that the work-report is valid. In the event of a negative judgment, then all validators audit said work-report and we assume a verdict will be reached. Auditing and guaranteeing are off-chain processes properly described in sections 14 and 17.

A judgment against a report implies that the chain is already reverted to some point prior to the accumulation of said report, usually forking at the block immediately prior to that at which accumulation happened. The specific strategy for chain selection is described fully in section 19. Authoring a block with a non-positive verdict has the effect of cancelling its imminent accumulation, as can be seen in equation eq:removenonpositive.

Registering a verdict also has the effect of placing a permanent record of the event on-chain and allowing any offending keys to be placed on-chain both immediately or in forthcoming blocks, again for permanent record.

Having a persistent on-chain record of misbehavior is helpful in a number of ways. It provides a very simple means of recognizing the circumstances under which action against a validator must be taken by any higher-level validator-selection logic. Should be used for a public network such as *Polkadot*, this would imply the slashing of the offending validator’s stake on the staking parachain.

As mentioned, recording reports found to have a high confidence of invalidity is important to ensure that said reports are not allowed to be resubmitted. Conversely, recording reports found to be valid ensures that additional disputes cannot be raised in the future of the chain.

## The State

The *disputes* state includes four items, three of which concern verdicts: a good-set ($\goodset$), a bad-set ($\badset$) and a wonky-set ($\wonkyset$) containing the hashes of all work-reports which were respectively judged to be correct, incorrect or that it appears impossible to judge. The fourth item, the punish-set ($\offenders$), is a set of Ed25519 keys representing validators which were found to have misjudged a work-report. $$\label{eq:disputesspec}
  \disputes \equiv \tup{\goodset, \badset, \wonkyset, \offenders}$$

## Extrinsic

The disputes extrinsic $\xtdisputes$ is functional grouping of three otherwise independent extrinsics. It comprises *verdicts* $\xtverdicts$, *culprits* $\xtculprits$, and *faults* $\xtfaults$. Verdicts are a compilation of judgments coming from exactly two-thirds plus one of either the active validator set or the previous epoch’s validator set, the Ed25519 keys of $\activeset$ or $\previousset$. Culprits and faults are proofs of the misbehavior of one or more validators, respectively either by guaranteeing a work-report found to be invalid, or by signing a judgment found to be contradiction to a work-report’s validity. Both of these are considered a kind of *offense*. Formally: $$\begin{aligned}
    \xtdisputes &\equiv \tuple{\xtverdicts, \xtculprits, \xtfaults} \\
    \where \xtverdicts &\in \sequence{\tuple{
      \hash,
      \ffrac{\thetime}{\Cepochlen} - \N_2,
      \sequence[\floor{\twothirds\Cvalcount} + 1]{\tuple{
        \set{\top, \bot},
        \valindex,
        \edsignaturebase
      }}
    }}\\
    \also \xtculprits &\in \sequence{\tuple{\hash, \edkey, \edsignaturebase}} \,,\quad
    \xtfaults \in \sequence{\tuple{\hash, \set{\top,\bot}, \edkey, \edsignaturebase}}
  \end{aligned}$$

The signatures of all judgments must be valid in terms of one of the two allowed validator key-sets, identified by the verdict’s second term which must be either the epoch index of the prior state or one less. Formally: $$\begin{aligned}
  &\begin{aligned}
    &\forall \tup{\xvSUBreporthash, \xvSUBepochindex, \xvSUBjudgments} \in \xtverdicts, \forall \tup{\xvjSUBvalidity, \xvjSUBjudgeindex, \xvjSUBsignature} \in \xvSUBjudgments : \xvjSUBsignature \in \edsignature{\mathbf{k}[\xvjSUBjudgeindex]_\vkSUBed}{\mathsf{X}\sub{v} \concat \xvSUBreporthash}\\
    &\quad\where \mathbf{k} = \begin{cases}
      \activeset &\when \xvSUBepochindex = \displaystyle \ffrac{\thetime}{\Cepochlen}\\
      \previousset &\otherwise\\
    \end{cases}
  \end{aligned}\\
  &\Xvalid \equiv \text{{\small \texttt{\$jam\_valid}}}\,,\ \Xinvalid \equiv \text{{\small \texttt{\$jam\_invalid}}}
\end{aligned}$$

Offender signatures must be similarly valid and reference work-reports with judgments and may not report keys which are already in the punish-set: $$\begin{aligned}
  \forall \tup{\xcSUBreporthash, \xcSUBoffenderindex, \xcSUBsignature} &\in \xtculprits : \bigwedge \abracegroup{
    &\xcSUBreporthash \in \badset' \,,\\
    &\xcSUBoffenderindex \in \mathbf{k} \,,\\
    &\xcSUBsignature \in \edsignature{\xcSUBoffenderindex}{\Xguarantee \concat \xcSUBreporthash}
  }\\
  \forall \tup{\xfSUBreporthash, \xfSUBvalidity, \xfSUBoffenderindex, \xfSUBsignature} &\in \xtfaults : \bigwedge \abracegroup{
    &\xfSUBreporthash \in \badset' \Leftrightarrow \xfSUBreporthash \not\in \goodset' \Leftrightarrow \xfSUBvalidity \,,\\
    &k \in \mathbf{k} \,,\\
    &s \in \edsignature{\xfSUBoffenderindex}{\mathsf{X}\sub{v} \concat \xfSUBreporthash}\\
  }\\
  \nonumber\where \mathbf{k} &= \set{\build{i_\vkSUBed}{i \in \previousset \cup \activeset}} \setminus \offenders
\end{aligned}$$

Verdicts $\xtverdicts$ must be ordered by report hash. Offender signatures $\xtculprits$ and $\xtfaults$ must each be ordered by the validator’s Ed25519 key. There may be no duplicate report hashes within the extrinsic, nor amongst any past reported hashes. Formally: $$\begin{aligned}
  &\xtverdicts = \sqorderuniqby{\xvSUBreporthash}{\tup{\xvSUBreporthash, \xvSUBepochindex, \xvSUBjudgments} \in \xtverdicts}\\
  &\xtculprits = \sqorderuniqby{\xcSUBoffenderindex}{\tup{\xcSUBreporthash, \xcSUBoffenderindex, \xcSUBsignature} \in \xtculprits} \,,\ 
  \xtfaults = \sqorderuniqby{\xfSUBoffenderindex}{\tup{\xfSUBreporthash, \xfSUBvalidity, \xfSUBoffenderindex, \xfSUBsignature} \in \xtfaults}\!\!\!\!\!\!\\
  &\set{\build{\xvSUBreporthash}{\tup{\xvSUBreporthash, \xvSUBepochindex, \xvSUBjudgments} \in \xtverdicts}} \disjoint \goodset \cup \badset \cup \wonkyset
\end{aligned}$$

The judgments of all verdicts must be ordered by validator index and there may be no duplicates: $$\forall \tup{\xvSUBreporthash, \xvSUBepochindex, \xvSUBjudgments} \in \xtverdicts : \xvSUBjudgments = \sqorderuniqby{\xvjSUBjudgeindex}{\tup{\xvjSUBvalidity, \xvjSUBjudgeindex, \xvjSUBsignature} \in \xvSUBjudgments}$$

We define $\mathbf{v}$ to derive from the sequence of verdicts introduced in the block’s extrinsic, containing only the report hash and the sum of positive judgments. We require this total to be either exactly two-thirds-plus-one, zero or one-third of the validator set indicating, respectively, that the report is good, that it’s bad, or that it’s wonky.[^11] Formally: $$\begin{aligned}
\label{eq:verdicts}
  \mathbf{v}&\in \sequence{\tup{
    \hash,
    \set{0, \floor{\onethird\Cvalcount}, \floor{\twothirds\Cvalcount} + 1}
  }} \\
  \mathbf{v}&= \sq{\build{
      \tup{
        \xvSUBreporthash,
        \sum_{\tup{\xvjSUBvalidity, \xvjSUBjudgeindex, \xvjSUBsignature} \in \xvSUBjudgments}\!\!\!\!
        \xvjSUBvalidity
      }
    }{
      \tup{\xvSUBreporthash, \xvSUBepochindex, \xvSUBjudgments} \orderedin \xtverdicts
    }}
\end{aligned}$$

There are some constraints placed on the composition of this extrinsic: any verdict containing solely valid judgments implies the same report having at least one valid entry in the faults sequence $\xtfaults$. Any verdict containing solely invalid judgments implies the same report having at least two valid entries in the culprits sequence $\xtculprits$. Formally: $$\begin{aligned}
  \forall \tup{\SUBreporthash, \floor{\twothirds\Cvalcount} + 1} \in \mathbf{v}&:
    \exists \tup{\SUBreporthash, \dots} \in \xtfaults \\
  \forall \tup{\SUBreporthash, 0} \in \mathbf{v}&:
    \len{\set{\tup{\SUBreporthash, \dots} \in \xtculprits}} \ge 2
\end{aligned}$$

We clear any work-reports which we judged as uncertain or invalid from their core: $$\label{eq:removenonpositive}
  \forall c \in \coreindex : \reportspostjudgement\subb{c} = \begin{cases}
    \none &\!\!\!\!\when
      \tup{\blake{\reports\subb{c}_\rsSUBworkreport}, t} \in \mathbf{v},
      t< \floor{\twothirds\Cvalcount} \\
    \reports\subb{c} &\!\!\!\!\otherwise
  \end{cases}\!\!\!\!\!\!\!$$

The state’s good-set, bad-set and wonky-set assimilate the hashes of the reports from each verdict. Finally, the punish-set accumulates the keys of any validators who have been found guilty of offending. Formally: $$\begin{aligned}
  \label{eq:goodsetdef}
  \goodset' &\equiv \goodset \cup \set{\build{
      \SUBreporthash
    }{
      \tup{\SUBreporthash, \floor{\twothirds\Cvalcount} + 1} \in \mathbf{v}
    }} \\
  \label{eq:badsetdef}
  \badset' &\equiv \badset \cup \set{\build{
      \SUBreporthash
    }{
      \tup{\SUBreporthash, 0} \in \mathbf{v}
    }} \\
  \label{eq:wonkysetdef}
  \!\!\wonkyset' &\equiv \wonkyset \cup \set{\build{
      \SUBreporthash
    }{
      \tup{\SUBreporthash, \floor{\onethird\Cvalcount}} \in \mathbf{v}
    }} \\
  \label{eq:offendersdef}
  \offenders' &\equiv \offenders \cup \set{\build{
      \SUBoffenderindex
    }{
      \tup{\SUBoffenderindex, \dots} \in \xtculprits
    }} \cup \set{\build{
      \SUBoffenderindex
    }{
      \tup{\SUBoffenderindex, \dots} \in \xtfaults
    }}\!\!\!\!
\end{aligned}$$

## Header

The offenders markers must contain exactly the keys of all new offenders, respectively. Formally: $$\begin{aligned}
  \H_\SUBoffendersmark &\equiv
    \sq{\build{\SUBoffenderindex}{\tup{\SUBoffenderindex,\dots} \orderedin \xtculprits}}
    \concat
    \sq{\build{\SUBoffenderindex}{\tup{\SUBoffenderindex,\dots} \orderedin \xtfaults}}
\end{aligned}$$

# Reporting and Assurance

Reporting and assurance are the two on-chain processes we do to allow the results of in-core computation to make their way into the state of service accounts, $\accounts$. A *work-package*, which comprises several *work-items*, is transformed by validators acting as *guarantors* into its corresponding *work-report*, which similarly comprises several *work-digests* and then presented on-chain within the *guarantees* extrinsic. At this point, the work-package is erasure coded into a multitude of segments and each segment distributed to the associated validator who then attests to its availability through an *assurance* placed on-chain. After enough assurances the work-report is considered *available*, and the work-digests transform the state of their associated service by virtue of accumulation, covered in section 12. The report may also be *timed-out*, implying it may be replaced by another report without accumulation.

From the perspective of the work-report, therefore, the guarantee happens first and the assurance afterwards. However, from the perspective of a block’s state-transition, the assurances are best processed first since each core may only have a single work-report pending its package becoming available at a time. Thus, we will first cover the transition arising from processing the availability assurances followed by the work-report guarantees. This synchroneity can be seen formally through the requirement of an intermediate state $\reportspostguarantees$, utilized later in equation eq:reportcoresareunusedortimedout.

## State

The state of the reporting and availability portion of the protocol is largely contained within $\reports$, which tracks the work-reports which have been reported but are not yet known to be available to a super-majority of validators, together with the time at which each was reported. As mentioned earlier, only one report may be assigned to a core at any given time. Formally: $$\label{eq:reportingstate}
  \reports \in \sequence[\Ccorecount]{
    \optional{\tuple{
      \isa{\rsSUBworkreport}{\workreport} ,\,
      \isa{\rsSUBtimestamp}{\timeslot}
    }}
  }$$

As usual, intermediate and posterior values ($\reportspostjudgement$, $\reportspostguarantees$, $\reportspostassurances$) are held under the same constraints as the prior value.

### Work Report

A work-report, of the set $\workreport$, is defined as a tuple of the work-package specification, $\wrSUBavspec$; the refinement context, $\wrSUBcontext$; the core-index (on which the work is done), $\wrSUBcore$; as well as the authorizer hash $\wrSUBauthorizer$ and trace $\wrSUBauthtrace$; a segment-root lookup dictionary $\wrSUBsrlookup$; the gas consumed during the Is-Authorized invocation, $\wrSUBauthgasused$; and finally the work-digests $\wrSUBdigests$ which comprise the results of the evaluation of each of the items in the package together with some associated data. Formally: $$\label{eq:workreport}
  \workreport \equiv \tuple{
    \begin{aligned}
      &\isa{\wrSUBavspec}{\avspec},\ 
      \isa{\wrSUBcontext}{\workcontext},\ 
      \isa{\wrSUBcore}{\coreindex},\ 
      \isa{\wrSUBauthorizer}{\hash},\ 
      \isa{\wrSUBauthtrace}{\blob},\\
      &\isa{\wrSUBsrlookup}{\dictionary{\hash}{\hash}},\ 
      \isa{\wrSUBdigests}{\sequence[1:\Cmaxpackageitems]{\workdigest}},\ 
      \isa{\wrSUBauthgasused}{\gas}
    \end{aligned}
  }$$

We limit the sum of the number of items in the segment-root lookup dictionary and the number of prerequisites to $\Cmaxreportdeps = 8$: $$\label{eq:limitreportdeps}
  \forall \wrX \in \workreport : \len{\wrX_\wrSUBsrlookup} + \len{(\wrX_\wrSUBcontext)_\wcSUBprerequisites} \le \Cmaxreportdeps$$

### Refinement Context

A *refinement context*, denoted by the set $\workcontext$, describes the context of the chain at the point that the report’s corresponding work-package was evaluated. It identifies two historical blocks, the *anchor*, header hash $\wcSUBanchorhash$ along with its associated posterior state-root $\wcSUBanchorpoststate$ and accumulation output log super-peak $\wcSUBanchoraccoutlog$; and the *lookup-anchor*, header hash $\wcSUBlookupanchorhash$ and of timeslot $\wcSUBlookupanchortime$. Finally, it identifies the hash of any prerequisite work-packages $\wcSUBprerequisites$. Formally: $$\label{eq:workcontext}
  \workcontext \equiv \tuple{\,\begin{alignedat}{5}
    \isa{\wcSUBanchorhash&}{\hash}\,,\;
    \isa{&\wcSUBanchorpoststate&}{\hash}\,,\;
    \isa{&\wcSUBanchoraccoutlog&}{\hash}\,,\;\\
    \isa{\wcSUBlookupanchorhash&}{\hash}\,,\;
    \isa{&\wcSUBlookupanchortime&}{\timeslot}\,,\;
    \isa{&\wcSUBprerequisites&}{\protoset{\hash}}
  \end{alignedat}}$$

### Availability

We define the set of *availability specifications*, $\avspec$, as the tuple of the work-package’s hash $\asSUBpackagehash$, an auditable work bundle length $\asSUBbundlelen$ (see section 14.4.1 for more clarity on what this is), together with an erasure-root $\asSUBerasureroot$, a segment-root $\asSUBsegroot$ and segment-count $\asSUBsegcount$. Work-results include this availability specification in order to ensure they are able to correctly reconstruct and audit the purported ramifications of any reported work-package. Formally: $$\begin{aligned}
  \label{eq:avspec}
  \avspec &\equiv \tuple{
    \isa{\asSUBpackagehash}{\hash}\,,\;
    \isa{\asSUBbundlelen}{\bloblength}\,,\;
    \isa{\asSUBerasureroot}{\hash}\,,\;
    \isa{\asSUBsegroot}{\hash}\,,\;
    \isa{\asSUBsegcount}{\N}
  }
\end{aligned}$$

The *erasure-root* ($\asSUBerasureroot$) is the root of a binary Merkle tree which functions as a commitment to all data required for the auditing of the report and for use by later work-packages should they need to retrieve any data yielded. It is thus used by assurers to verify the correctness of data they have been sent by guarantors, and it is later verified as correct by auditors. It is discussed fully in section 14.

The *segment-root* ($\asSUBsegroot$) is the root of a constant-depth, left-biased and zero-hash-padded binary Merkle tree committing to the hashes of each of the exported segments of each work-item. These are used by guarantors to verify the correctness of any reconstructed segments they are called upon to import for evaluation of some later work-package. It is also discussed in section 14.

### Work Digest

We finally come to define a *work-digest*, $\workdigest$, which is the data conduit by which services’ states may be altered through the computation done within a work-package. $$\label{eq:workdigest}
  \workdigest \equiv \tuple{
    \begin{alignedat}{9}
      \isa{\wdSUBserviceindex&}{\serviceid}\,,\;
      \isa{&\wdSUBcodehash&}{\hash}\,,\;
      \isa{&\wdSUBpayloadhash&}{\hash}\,,\;
      \isa{&\wdSUBgaslimit&}{\gas}\,,\;
      \isa{&\wdSUBresult&}{\blob \cup \workerror}\,,\;\\
      \isa{\wdSUBgasused&}{\gas}\,,\;
      \isa{&\wdSUBimportcount&}{\N}\,,\;
      \isa{&\wdSUBxtcount&}{\N}\,,\;
      \isa{&\wdSUBxtsize&}{\N}\,,\;
      \isa{&\wdSUBexportcount&}{\N}
    \end{alignedat}
  }$$

Work-digests are a tuple comprising several items. Firstly $\wdSUBserviceindex$, the index of the service whose state is to be altered and thus whose refine code was already executed. We include the hash of the code of the service at the time of being reported $\wdSUBcodehash$, which must be accurately predicted within the work-report according to equation eq:reportcodesarecorrect.

Next, the hash of the payload ($\wdSUBpayloadhash$) within the work item which was executed in the refine stage to give this result. This has no immediate relevance, but is something provided to the accumulation logic of the service. We follow with the gas limit $\wdSUBgaslimit$ for executing this item’s accumulate.

There is the work *result*, the output blob or error of the execution of the code, $\wdSUBresult$, which may be either an octet sequence in case it was successful, or a member of the set $\workerror$, if not. This latter set is defined as the set of possible errors, formally: $$\label{eq:workerror}
  \workerror \in \set{ \oog, \panic, \badexports, \oversize, \token{BAD}, \token{BIG} }$$

The first two are special values concerning execution of the virtual machine, $\oog$ denoting an out-of-gas error and $\panic$ denoting an unexpected program termination. Of the remaining four, the first indicates that the number of exports made was invalidly reported, the second that the size of the digest (refinement output) would cross the acceptable limit, the third indicates that the service’s code was not available for lookup in state at the posterior state of the lookup-anchor block. The fourth indicates that the code was available but was beyond the maximum size allowed $\Cmaxservicecodesize$.

Finally, we have five fields describing the level of activity which this workload imposed on the core in bringing the result to bear. We include $\wdSUBgasused$ the actual amount of gas used during refinement; $\wdSUBimportcount$ and $\wdSUBexportcount$ the number of segments imported from, and exported into, the D$^3$L respectively; and $\wdSUBxtcount$ and $\wdSUBxtsize$ the number of, and total size in octets of, the extrinsics used in computing the workload. See section 14 for more information on the meaning of these values.

In order to ensure fair use of a block’s extrinsic space, work-reports are limited in the maximum total size of the successful refinement output blobs together with the authorizer trace, effectively limiting their overall size: $$\begin{aligned}
  \label{eq:limitworkreportsize}
  &\forall \wrX \in \workreport:
    \len{\wrX_\wrSUBauthtrace} + \sum_{\wdX \in \wrX_\wrSUBdigests \cap \blob} \len{\wdX_\wdSUBresult} \le \Cmaxreportvarsize \\
  &\Cmaxreportvarsize \equiv 48\cdot2^{10}
\end{aligned}$$

## Package Availability Assurances

We first define $\reportspostguarantees$, the intermediate state to be utilized next in section 11.4 as well as $\justbecameavailable$, the set of available work-reports, which will we utilize later in section 12. Both require the integration of information from the assurances extrinsic $\xtassurances$.

### The Assurances Extrinsic

The assurances extrinsic is a sequence of *assurance* values, at most one per validator. Each assurance is a sequence of binary values (a bitstring), one per core, together with a signature and the index of the validator who is assuring. A value of $1$ (or $\top$, if interpreted as a Boolean) at any given index implies that the validator assures they are contributing to its availability.[^12] Formally: $$\begin{aligned}
  \label{eq:xtassurances}
  \xtassurances \in \sequence[\mathsf{:\Cvalcount}]{\tuple{
    \isa{\xaSUBanchor}{\hash},\,
    \isa{\xaSUBavailabilities}{\bitstring[\Ccorecount]},\,
    \isa{\xaSUBassurer}{\valindex},\,
    \isa{\xaSUBsignature}{\edsignaturebase}
  }}
\end{aligned}$$

The assurances must all be anchored on the parent and ordered by validator index: $$\begin{aligned}
  \forall a &\in \xtassurances : a_\xaSUBanchor = \H_\SUBparent \\
  \forall i &\in \set{ 1 \dots \len{\xtassurances} } : \xtassurances\subb{i - 1}_\xaSUBassurer < \xtassurances\subb{i}_\xaSUBassurer
\end{aligned}$$

The signature must be one whose public key is that of the validator assuring and whose message is the serialization of the parent hash $\H_\SUBparent$ and the aforementioned bitstring: $$\begin{aligned}
  \label{eq:assurancesig}
  &\forall a \in \xtassurances : a_\xaSUBsignature \in \edsignature{\activeset\subb{a_\xaSUBassurer}_\vkSUBed}{\Xavailable \concat \blake{\encode{\H_\SUBparent, a_\xaSUBavailabilities}}} \\
  &\Xavailable \equiv \token{\$jam\_available}
\end{aligned}$$

A bit may only be set if the corresponding core has a report pending availability on it: $$\forall a \in \xtassurances, \cX \in \coreindex :
  \quad a_\xaSUBavailabilities\subb{\cX} \Rightarrow \reportspostjudgement\subb{\cX} \ne \none$$

### Available Reports

A work-report is said to become *available* if and only if there are a clear super-majority of validators who have marked its core as set within the block’s assurance extrinsic. Formally, we define the sequence of newly available work-reports $\justbecameavailable$ as: $$\begin{aligned}
  \label{eq:availableworkreports}
  \justbecameavailable &\equiv \sq{\build{
      \reportspostjudgement\subb{\cX}_\rsSUBworkreport
    }{
      \cX \orderedin \coreindex,\;
      \sum_{a \in \xtassurances}\!a_\xaSUBavailabilities\subb{\cX}\,>\,\twothirds\,\Cvalcount
    }}
\end{aligned}$$

This value is utilized in the definition of both $\accountspost$ and $\reportspostguarantees$ which we will define presently as equivalent to $\reportspostjudgement$ except for the removal of items which are either now available or have timed out: $$\begin{aligned}
  \label{eq:reportspostguaranteesdef}
  \forall \cX \in \coreindex: \reportspostguarantees\subb{\cX} \equiv \begin{cases}
    \none &\when\reports\subb{\cX}_\rsSUBworkreport \in \justbecameavailable \vee \H_\SUBtimeslot \ge \reportspostjudgement\subb{\cX}_\rsSUBtimestamp + \Cassurancetimeoutperiod\\
    \reportspostjudgement\subb{\cX} &\otherwise
  \end{cases}
\end{aligned}$$

## Guarantor Assignments

Every block, each core has three validators uniquely assigned to guarantee work-reports for it. This is borne out with $\Cvalcount = 1,023$ validators and $\Ccorecount = 341$ cores, since $\nicefrac{\Cvalcount}{\Ccorecount} = 3$. The core index assigned to each of the validators, as well as the validators’ keys are denoted by $\guarantorassignments$: $$\guarantorassignments \in \tuple{\sequence[\Cvalcount]{\coreindex}, \allvalkeys}$$

We determine the core to which any given validator is assigned through a shuffle using epochal entropy and a periodic rotation to help guard the security and liveness of the network. We use $\entropy_2$ for the epochal entropy rather than $\entropy_1$ to avoid the possibility of fork-magnification where uncertainty about chain state at the end of an epoch could give rise to two established forks before it naturally resolves.

We define the permute function $P$, the rotation function $R$ and finally the guarantor assignments $\guarantorassignments$ as follows: $$\begin{aligned}
  R(\mathbf{c}, n) &\equiv \sq{\build{(x + n) \bmod \Ccorecount}{x \orderedin \mathbf{c}}}\\
  P(e, t) &\equiv R\left(
    \fyshuffle{\sq{\build{\ffrac{\Ccorecount \cdot i}{\Cvalcount}}{i \orderedin \valindex}}, e},
    \ffrac{t \bmod \Cepochlen}{\Crotationperiod}
  \right)\\
  \guarantorassignments &\equiv \tup{P(\entropy'_2, \thetime'), \Phi(\activeset')}
\end{aligned}$$

We also define $\guarantorassignmentsunderlastrotation$, which is equivalent to the value $\guarantorassignments$ as it would have been under the previous rotation: $$\label{eq:priorassignments}
  \begin{aligned}
    \using \tup{e, \mathbf{k}} &= \begin{cases}
      \tup{\entropy'_2, \activeset'} &\when \displaystyle\ffrac{\thetime' - \Crotationperiod}{\Cepochlen} = \ffrac{\thetime'}{\Cepochlen}\\
      \tup{\entropy'_3, \previousset'} &\otherwise
    \end{cases} \\
    \guarantorassignmentsunderlastrotation &\equiv \tup{
      P(e, \thetime' - \Crotationperiod),
      \Phi(\mathbf{k})
    }
  \end{aligned}$$

## Work Report Guarantees

We begin by defining the guarantees extrinsic, $\xtguarantees$, a series of *guarantees*, at most one for each core, each of which is a tuple of a *work-report*, a credential $\xgSUBcredential$ and its corresponding timeslot $\xgSUBtimeslot$. The core index of each guarantee must be unique and guarantees must be in ascending order of this. Formally: $$\begin{aligned}
\label{eq:guaranteesextrinsic}
  \xtguarantees &\in \sequence[:\Ccorecount]{\tuple{
    \isa{\xgSUBworkreport}{\workreport},\,
    \isa{\xgSUBtimeslot}{\timeslot},\,
    \isa{\xgSUBcredential}{\sequence[2:3]{\tuple{\valindex, \edsignaturebase}}}
  }} \\
  \xtguarantees &= \sqorderuniqby{(g_\xgSUBworkreport)_\wrSUBcore}{g \in \xtguarantees}
\end{aligned}$$

The credential is a sequence of two or three tuples of a unique validator index and a signature. Credentials must be ordered by their validator index: $$\begin{aligned}
  \forall g &\in \xtguarantees : g_\xgSUBcredential = \sqorderuniqby{v}{\tup{v, s} \in g_\xgSUBcredential}
\end{aligned}$$

The signature must be one whose public key is that of the validator identified in the credential, and whose message is the serialization of the hash of the work-report. The signing validators must be assigned to the core in question in either this block $\guarantorassignments$ if the timeslot for the guarantee is in the same rotation as this block’s timeslot, or in the most recent previous set of assignments, $\guarantorassignmentsunderlastrotation$: $$\begin{aligned}
  \label{eq:guarantorsig}
  &\begin{aligned}
    &\begin{aligned}
      \forall \tup{\xgSUBworkreport, \xgSUBtimeslot, \xgSUBcredential} &\in \xtguarantees,\\
      \forall \tup{v, s} &\in \xgSUBcredential
    \end{aligned} :
      \abracegroup[\,]{
        &s \in \edsignature{(\mathbf{k}\sub{v})_\vkSUBed}{\Xguarantee\concat\blake{\xgSUBworkreport}}\\
        &\mathbf{c}\sub{v} = \wrX_\wrSUBcore \wedge \Crotationperiod(\floor{\nicefrac{\thetime'}{\Crotationperiod}} - 1) \le \xgSUBtimeslot \le \thetime'\\
      }\\
      &k \in \reporters \Leftrightarrow \exists \tup{\xgSUBworkreport, \xgSUBtimeslot, \xgSUBcredential} \in \xtguarantees, \exists \tup{v, s} \in \xgSUBcredential: k = (\mathbf{k}\sub{v})_\vkSUBed\\
      &\quad\where \tup{\mathbf{c}, \mathbf{k}} = \begin{cases}
        \guarantorassignments &\when \displaystyle \ffrac{\thetime'}{\Crotationperiod} = \ffrac{t}{\Crotationperiod} \\
        \guarantorassignmentsunderlastrotation &\otherwise
      \end{cases}
  \end{aligned}\\
  &\Xguarantee \equiv \token{\$jam\_guarantee}
\end{aligned}$$

We note that the Ed25519 key of each validator whose signature is in a credential is placed in the *reporters* set $\reporters$. This is utilized by the validator activity statistics bookkeeping system section 13.

We denote $\incomingreports$ to be the set of work-reports in the present extrinsic $\theextrinsic$: $$\begin{aligned}
\label{eq:incomingworkreports}
  \using\incomingreports = \set{ \build { \xgX_\xgSUBworkreport }{ \xgX \in \xtguarantees } }
\end{aligned}$$

No reports may be placed on cores with a report pending availability on it. A report is valid only if the authorizer hash is present in the authorizer pool of the core on which the work is reported. Formally: $$\label{eq:reportcoresareunusedortimedout}
  \forall \wrX \in \incomingreports :
    \reportspostguarantees\subb{\wrX_\wrSUBcore} = \none \wedge \wrX_\wrSUBauthorizer \in \authpool\subb{\wrX_\wrSUBcore}$$

We require that the gas allotted for accumulation of each work-digest in each work-report respects its service’s minimum gas requirements. We also require that all work-reports’ total allotted accumulation gas is no greater than the overall gas limit $\Creportaccgas$: $$\forall \wrX \in \incomingreports:
    \sum_{\wdX \in \wrX_\wrSUBdigests}\!(\wdX_\wdSUBgaslimit) \le \Creportaccgas \ \wedge \ 
    \forall \wdX \in \wrX_\wrSUBdigests: \wdX_\wdSUBgaslimit \ge \accounts\subb{\wdX_\wdSUBserviceindex}_\saSUBminaccgas$$

### Contextual Validity of Reports

For convenience, we define two equivalences $\mathbf{x}$ and $\mathbf{p}$ to be, respectively, the set of all contexts and work-package hashes within the extrinsic: $$\using \mathbf{x}\equiv \set{ \build { \wrX_\wrSUBcontext }{ \wrX \in \incomingreports } }\ ,\quad
    \mathbf{p}\equiv \set{ \build { (\wrX_\wrSUBavspec)_\asSUBpackagehash }{ \wrX \in \incomingreports } }$$

There must be no duplicate work-package hashes (two work-reports of the same package). Therefore, we require the cardinality of $\mathbf{p}$ to be the length of the work-report sequence $\incomingreports$: $$\len{\mathbf{p}} = \len{\incomingreports}$$

We require that the anchor block be within the last $\Crecenthistorylen$ blocks and that its details be correct by ensuring that it appears within our most recent blocks $\recenthistorypostparentstaterootupdate$: $$\begin{aligned}
  \forall x \in \mathbf{x}: \exists y \in \recenthistorypostparentstaterootupdate : x_\wcSUBanchorhash = y_\rhSUBheaderhash \wedge x_\wcSUBanchorpoststate = y_\rhSUBstateroot \wedge x_\wcSUBanchoraccoutlog = y_\rhSUBaccoutlogsuperpeak \!\!\!\!\!\!
\end{aligned}$$

We require that each lookup-anchor block be within the last $\Cmaxlookupanchorage$ timeslots: $$\begin{aligned}
  \label{eq:limitlookupanchorage}
  \forall x \in \mathbf{x}:\ x_\wcSUBlookupanchortime \ge \H_\SUBtimeslot - \Cmaxlookupanchorage
\end{aligned}$$

We also require that we have a record of it; this is one of the few conditions which cannot be checked purely with on-chain state and must be checked by virtue of retaining the series of the last $\Cmaxlookupanchorage$ headers as the ancestor set $\ancestors$. Since it is determined through the header chain, it is still deterministic and calculable. Formally: $$\begin{aligned}
  \forall x \in \mathbf{x}:\ \exists h \in \ancestors: h_\SUBtimeslot = x_\wcSUBlookupanchortime \wedge \blake{h} = x_\wcSUBlookupanchorhash
\end{aligned}$$

We require that the work-package of the report not be the work-package of some other report made in the past. We ensure that the work-package not appear anywhere within our pipeline. Formally: $$\begin{aligned}
  &\using \mathbf{q} = \set{\build{
      (\wrX_\wrSUBavspec)_\asSUBpackagehash
    }{
      \tup{\wrX, \mathbf{d}} \in \concatall{\ready}
    }} \\
  &\using \mathbf{a} = \set{\build{
      ((\wrX_\rsSUBworkreport)_\wrSUBavspec)_\asSUBpackagehash
    }{
      \wrX \in \reports, \wrX \ne \none
    }} \\
  &\forall p \in \mathbf{p},
    p \not\in \bigcup_{x \in \recenthistory}\keys{x_\rhSUBreportedpackagehashes}
      \cup
      \bigcup_{x \in \accumulated}x
      \cup \mathbf{q}
      \cup \mathbf{a}
\end{aligned}$$

We require that the prerequisite work-packages, if present, and any work-packages mentioned in the segment-root lookup, be either in the extrinsic or in our recent history. $$\begin{aligned}
  &\begin{aligned}
    &\forall \wrX \in \incomingreports,
    \forall p \in (\wrX_\wrSUBcontext)_\wcSUBprerequisites \cup
      \keys{\wrX_\wrSUBsrlookup} :\\
    &\quad p \in \mathbf{p}\cup \set{
      \build{x}{x \in \keys{b_\rhSUBreportedpackagehashes},\, b \in \recenthistory}}
  \end{aligned}
\end{aligned}$$

We require that any segment roots mentioned in the segment-root lookup be verified as correct based on our recent work-package history and the present block: $$\begin{aligned}
  &\using \mathbf{p}= \set{ \build {
    \kv{
      ((g_\xgSUBworkreport)_\wrSUBavspec)_\asSUBpackagehash
    }{
      ((g_\xgSUBworkreport)_\wrSUBavspec)_\asSUBsegroot
    }
  }{
    g \in \xtguarantees
  } } \\
  &\forall \wrX \in \incomingreports: \wrX_\wrSUBsrlookup \subseteq \mathbf{p}\cup \bigcup_{b \in \recenthistory} b_\rhSUBreportedpackagehashes
\end{aligned}$$

(Note that these checks leave open the possibility of accepting work-reports in apparent dependency loops. We do not consider this a problem: the pre-accumulation stage effectively guarantees that accumulation never happens in these cases and the reports are simply ignored.)

Finally, we require that all work-digests within the extrinsic predicted the correct code hash for their corresponding service: $$\begin{aligned}
\label{eq:reportcodesarecorrect}
  \forall \wrX \in \incomingreports, \forall \wdX \in \wrX_\wrSUBdigests : \wdX_\wdSUBcodehash = \accounts\subb{\wdX_\wdSUBserviceindex}_\saSUBcodehash
\end{aligned}$$

## Transitioning for Reports

We define $\reportspostassurances$ as being equivalent to $\reportspostguarantees$, except where the extrinsic replaced an entry. In the case an entry is replaced, the new value includes the present time $\thetime'$ allowing for the value to be replaced without respect to its availability once sufficient time has elapsed (see equation eq:reportcoresareunusedortimedout). $$\forall \cX \in \coreindex : \reportspostassurances\subb{\cX} \equiv \begin{cases}
      \tup{\SUBworkreport,\,\is{\rsSUBtimestamp}{\thetime'}} &\when \exists \tup{\SUBworkreport,\,\xgSUBtimeslot,\,\xgSUBcredential} \in \xtguarantees, \SUBworkreport_\wrSUBcore = \cX \\
      \reportspostguarantees\subb{\cX} &\otherwise
    \end{cases}$$

This concludes the section on reporting and assurance. We now have a complete definition of $\reportspostassurances$ together with $\justbecameavailable$ to be utilized in section 12, describing the portion of the state transition happening once a work-report is guaranteed and made available.

# Accumulation

Accumulation may be defined as some function whose arguments are $\justbecameavailable$ and $\accounts$ together with selected portions of (at times partially transitioned) state and which yields the posterior service state $\accountspostpreimage$ together with additional state elements $\stagingset'$, $\authqueue'$ and $\privileges'$.

The proposition of accumulation is in fact quite simple: we merely wish to execute the *Accumulate* logic of the service code of each of the services which has at least one work-digest, passing to it relevant data from said digests together with useful contextual information. However, there are three main complications. Firstly, we must define the execution environment of this logic and in particular the host functions available to it. Secondly, we must define the amount of gas to be allowed for each service’s execution. Finally, we must determine the nature of transfers within Accumulate.

## History and Queuing

Accumulation of a work-report is deferred in the case that it has a not-yet-fulfilled dependency and is cancelled entirely in the case of an invalid dependency. Dependencies are specified as work-package hashes and in order to know which work-packages have been accumulated already, we maintain a history of what has been accumulated. This history, $\accumulated$, is sufficiently large for an epoch worth of work-reports. Formally: $$\begin{aligned}
  \label{eq:accumulatedspec}
  \accumulated &\in \sequence[\Cepochlen]{\protoset{\hash}} \\
  \accumulatedcup &\equiv \bigcup_{x \in \accumulated}(x)
\end{aligned}$$

We also maintain knowledge of ready (available and/or audited) but not-yet-accumulated work-reports in the state item $\ready$. Each of these were made available at most one epoch ago but have or had unfulfilled dependencies. Alongside the work-report itself, we retain its unaccumulated dependencies, a set of work-package hashes. Formally: $$\begin{aligned}
  \label{eq:readyspec}
  \ready &\in \sequence[\Cepochlen]{\sequence{\tuple{\workreport, \protoset{\hash}}}}
\end{aligned}$$

The newly available work-reports, $\justbecameavailable$, are partitioned into two sequences based on the condition of having zero prerequisite work-reports. Those meeting the condition, $\justbecameavailable^!$, are accumulated immediately. Those not, $\justbecameavailable^Q$, are for queued execution. Formally: $$\begin{aligned}
  \justbecameavailable^! &\equiv \sq{\build{r}{r \orderedin \justbecameavailable, \len{(r_\wrSUBcontext)_\wcSUBprerequisites} = 0 \wedge r_\wrSUBsrlookup = \emset}} \\
  \justbecameavailable^Q &\equiv E(\sq{
    D(r) \mid
    r \orderedin \justbecameavailable,
    \len{(r_\wrSUBcontext)_\wcSUBprerequisites} > 0 \vee r_\wrSUBsrlookup \ne \emset
  }, \accumulatedcup)\!\!\!\!\\
  D(r) &\equiv (r, \set{(r_\wrSUBcontext)_\wcSUBprerequisites} \cup \keys{r_\wrSUBsrlookup})
\end{aligned}$$

We define the queue-editing function $E$, which is essentially a mutator function for items such as those of $\ready$, parameterized by sets of now-accumulated work-package hashes (those in $\accumulated$). It is used to update queues of work-reports when some of them are accumulated. Functionally, it removes all entries whose work-report’s hash is in the set provided as a parameter, and removes any dependencies which appear in said set. Formally: $$E\colon\abracegroup{
      &\tuple{\sequence{\tuple{\workreport, \protoset{\hash}}}, \protoset{\hash}} \to \sequence{\tuple{\workreport, \protoset{\hash}}} \\
    &\tup{\mathbf{r}, \mathbf{x}} \mapsto \sq{\build{
      \tup{r, \mathbf{d} \setminus \mathbf{x}}
    }{
      \begin{aligned}
        &\tup{r, \mathbf{d}} \orderedin \mathbf{r} ,\\
        &(r_\wrSUBavspec)_\asSUBpackagehash \not\in \mathbf{x}
      \end{aligned}
    }}
  }$$

We further define the accumulation priority queue function $Q$, which provides the sequence of work-reports which are able to be accumulated given a set of not-yet-accumulated work-reports and their dependencies. $$Q\colon\abracegroup{
    &\sequence{\tuple{\workreport, \protoset{\hash}}} \to \workreports \\
    &\mathbf{r} \mapsto \begin{cases}
      \sq{} &\when \mathbf{g} = \sq{} \\
      \mathbf{g} \concat Q(E(\mathbf{r}, P(\mathbf{g})))\!\!\!\! &\otherwise \\
      \multicolumn{2}{l}{\,\where \mathbf{g} = \sq{\build{r}{\tup{r, \emset} \orderedin \mathbf{r}}}}
    \end{cases}
  }$$

Finally, we define the mapping function $P$ which extracts the corresponding work-package hashes from a set of work-reports: $$P\colon\abracegroup{
    \protoset{\workreport} &\to \protoset{\hash}\\
    \mathbf{r} &\mapsto \set{
      \build{(r_\wrSUBavspec)_\asSUBpackagehash}{r \in \mathbf{r}}
    }
  }$$

We may now define the sequence of accumulatable work-reports in this block as $\justbecameavailable^*$: $$\begin{aligned}
  \using m &= \H_\SUBtimeslot \bmod \Cepochlen\\
  \justbecameavailable^* &\equiv \justbecameavailable^! \concat Q(\mathbf{q}) \\
  \quad\where \mathbf{q} &= E(\concatall{\ready\interval{m}{}} \concat \concatall{\ready\interval{}{m}} \concat \justbecameavailable^Q, P(\justbecameavailable^!))
\end{aligned}$$

## Execution

We work with a limited amount of gas per block and therefore may not be able to process all items in $\justbecameavailable^*$ in a single block. There are two slightly antagonistic factors allowing us to optimize the amount of work-items, and thus work-reports, accumulated in a single block:

Firstly, while we have a well-known gas-limit for each work-item to be accumulated, accumulation may still result in a lower amount of gas used. Only after a work-item is accumulated can it be known if it uses less gas than the advertised limit. This implies a sequential execution pattern.

Secondly, since PVM setup cannot be expected to be zero-cost, we wish to amortize this cost over as many work-items as possible. This can be done by aggregating work-items associated with the same service into the same PVM invocation. This implies a non-sequential execution pattern.

We resolve this by defining a function $\accseq$ which accumulates work-reports sequentially, and which itself utilizes a function $\accpar$ which accumulates work-reports in a non-sequential, service-aggregated manner. In all but the first invocation of $\accseq$, we also integrate the effects of any *deferred-transfers* implied by the previous round of accumulation, thus the accumulation function must accept both the information contained in work-digests and that of deferred-transfers.

Rather than passing whole work-digests into accumulate, we extract the salient information from them and combine with information implied by their work-reports. We call this kind of combined value an *operand tuple*, $\operandtuple$. Likewise, we denote the set characterizing a *deferred transfer* as $\defxfer$, noting that a transfer includes a memo component $\dxSUBmemo$ of $\Cmemosize = 128$ octets, together with the service index of the sender $\dxSUBsource$, the service index of the receiver $\dxSUBdest$, the balance to be transferred $\dxSUBamount$ and the gas limit $\dxSUBgas$ for the transfer. Formally: $$\begin{aligned}
  \label{eq:operandtuple}
  \operandtuple &\equiv \tuple{
    \begin{alignedat}{5}
      \isa{\otSUBpackagehash&}{\hash},\;
      \isa{&\otSUBsegroot&}{\hash},\;
      \isa{&\otSUBauthorizer&}{\hash},\;
      \isa{\otSUBpayloadhash}{\hash},\;\\
      \isa{\otSUBgaslimit&}{\gas},\;
      \isa{&\otSUBauthtrace&}{\blob},\;
      \isa{&\otSUBresult&}{\blob \cup \workerror}
    \end{alignedat}
  }\\
  \label{eq:defxfer}
  \defxfer &\equiv \tuple{
    \isa{\dxSUBsource}{\serviceid} ,
    \isa{\dxSUBdest}{\serviceid} ,
    \isa{\dxSUBamount}{\balance} ,
    \isa{\dxSUBmemo}{\memo} ,
    \isa{\dxSUBgas}{\gas}
  }\\
  \label{eq:accinput}
  \accinput &\equiv \operandtuple \cup \defxfer
\end{aligned}$$

Note that the union of the two is the *accumulation input*, $\accinput$.

Our formalisms continue by defining $\partialstate$ as a characterization of (values capable of representing) state components which are both needed and mutable by the accumulation process. This comprises the service accounts state (as in $\accountspre$), the upcoming validator keys $\stagingset$, the queue of authorizers $\authqueue$ and the privileges state $\privileges$. Formally: $$\label{eq:partialstate}
  \partialstate \equiv \tuple{\begin{aligned}
    &\isa{\psSUBaccounts}{\dictionary{\serviceid}{\serviceaccount}} \,,\;
    \isa{\psSUBstagingset}{\sequence[\Cvalcount]{\valkey}} \,,\;
    \isa{\psSUBauthqueue}{\sequence[\Ccorecount]{\sequence[\Cauthqueuesize]{\hash}}} \,,\;
    \isa{\psSUBmanager}{\serviceid} \,,\\
    &\isa{\psSUBassigners}{\sequence[\Ccorecount]{\serviceid}} \,,\;
    \isa{\psSUBdelegator}{\serviceid} \,,\;
    \isa{\psSUBregistrar}{\serviceid} \,,\;
    \isa{\psSUBalwaysaccers}{\dictionary{\serviceid}{\gas}}
  \end{aligned}}$$

Finally, we define $B$ and $U$, the sets characterizing service-indexed commitments to accumulation output and service-indexed gas usage respectively: $$B\equiv \protoset{\tuple{\serviceid, \hash}} \qquad
  U\equiv \sequence{\tuple{\serviceid, \gas}}$$

We define the outer accumulation function $\accseq$ which transforms a gas-limit, a sequence of deferred transfers, a sequence of work-reports, an initial partial-state and a dictionary of services enjoying free accumulation, into a tuple of the number of work-reports accumulated, a posterior state-context, the resultant accumulation-output pairings and the service-indexed gas usage: $$\label{eq:accseq}
  \accseq\colon\abracegroup{
    &\tuple{\gas, \defxfers, \workreports, \partialstate, \dictionary{\serviceid}{\gas}} \to \tuple{\N, \partialstate, B, U} \\
    &\tup{g, \mathbf{t}, \mathbf{r}, \psX, \mathbf{f}} \!\mapsto\! \begin{cases}
      \tup{0, \psX, \emset, \sq{}} &
        \when n = 0 \\
      \tup{i + j, \psX', \mathbf{b}^* \!\cup \mathbf{b}, \mathbf{u}^* \!\!\concat \mathbf{u}}\!\!\!\! &
        \text{o/w}\!\!\!\!\!\!\!\! \\
    \end{cases} \\
    &\quad\where i = \max(\Nmax{\len{\mathbf{r}} + 1}): \sum_{r \in \mathbf{r}\sub{\dots i}, d \in r_\wrSUBdigests}(d_\wdSUBgaslimit) \le g \\
    &\quad\also n = \len{\mathbf{t}} + i + \len{\mathbf{f}} \\
    &\quad\also \tup{\psX^*\!\!, \mathbf{t}^*\!\!, \mathbf{b}^*\!\!, \mathbf{u}^*} = \accpar(\psX, \mathbf{t},\mathbf{r}\sub{\dots i}, \mathbf{f}) \\
    &\quad\also \tup{j, \psX'\!, \mathbf{b}, \mathbf{u}} = \accseq(g^* - \!\!\!\!\!\!\sum_{\tup{s, u} \in \mathbf{u}^*}\!\!\!\!\!\!(u), \mathbf{t}^*\!\!, \mathbf{r}\sub{i\dots}, \psX^*\!\!, \emset)\\
    &\quad\also g^* = g + \sum_{t \in \mathbf{t}}(t_\dxSUBgas)
  }$$

We come to define the parallelized accumulation function $\accpar$ which, with the help of the single-service accumulation function $\accone$, transforms an initial state-context, together with a sequence of deferred transfers, a sequence of work-reports and a dictionary of privileged always-accumulate services, into a tuple of the posterior state-context, the resultant deferred-transfers and accumulation-output pairings, and the service-indexed gas usage. Note that for the privileges we employ a function $R$ which selects the service to which the manager service changed, or if no change was made, then that which the service itself changed to. This allows privileges to be ‘owned‘ and facilitates the removal of the manager service which we see as a helpful possibility. Formally: $$\label{eq:accpar}
  \accpar\colon\abracegroup[\;]{\begin{aligned}
    &\tuple{\partialstate, \defxfers, \workreports, \dictionary{\serviceid}{\gas}} \to \tuple{\partialstate, \defxfers, B, U} \\
    &\tup{\psX, \mathbf{t}, \mathbf{r}, \mathbf{f}} \mapsto \tup{
      \tup{
        \psSUBaccounts', \psSUBstagingset', \psSUBauthqueue', \psSUBmanager', \psSUBassigners', \psSUBdelegator', \psSUBregistrar', \psSUBalwaysaccers'
      }, \concatall{\mathbf{t}'}, \mathbf{b}, \mathbf{u}
    }\!\!\!\!\!\!\\
    &\text{where:}\\
    &\ \begin{aligned}
      \using \mathbf{s} &= \set{\build{
        d_\wdSUBserviceindex
        }{
          r \in \mathbf{r}, d \in r_\wrSUBdigests
        }} \cup \keys{\mathbf{f}} \cup \set{\build{t_\dxSUBdest}{t \in \mathbf{t}}} \\
      \accumulate(s) &\equiv \accone(\psX, \mathbf{t}, \mathbf{r}, \mathbf{f}, s) \\
      \mathbf{u} &= \sq{\build{
          \tup{s, \accumulate(s)_\aoSUBgasused}
        }{
          s \orderedin \mathbf{s}
        }} \\
      \mathbf{b} &= \set{\build{
          \tup{s, b}
        }{
          s \in \mathbf{s},\,
          b = \accumulate(s)_\aoSUByield,\,
          b \ne \none
        }} \\
      \mathbf{t}' &= \sq{\build{
          \accumulate(s)_\aoSUBdefxfers
        }{
          s \orderedin \mathbf{s}
        }} \\
      \psSUBaccounts' &= I(
        (\psSUBaccounts \cup \mathbf{n}) \setminus \mathbf{m},
        \bigcup_{s \in \mathbf{s}} \accumulate(s)_\aoSUBprovisions
      ) \\
      &\tup{
        \psSUBaccounts, \psSUBstagingset, \psSUBauthqueue, \psSUBmanager, \psSUBassigners, \psSUBdelegator, \psSUBregistrar, \psSUBalwaysaccers
      } = \psX \\
      \mathbf{e}^*&= \accumulate(m)_\aoSUBpoststate \\
      \tup{\psSUBmanager'\!,\psSUBalwaysaccers'} &=
        \mathbf{e}^*_{\tup{\psSUBmanager, \psSUBalwaysaccers}} \\
      \forall c \in \coreindex :
        \psSUBassigners'\sub{c} &= R(
          \psSUBassigners\sub{c},
          (\mathbf{e}^*_\psSUBassigners)\sub{c},
          ((\accumulate(\psSUBassigners\sub{c})_\aoSUBpoststate)_\psSUBassigners)\sub{c}
        ) \\
      \psSUBdelegator' &= R(
        \psSUBdelegator,
        \mathbf{e}^*_\psSUBdelegator,
        (\accumulate(\psSUBdelegator)_\aoSUBpoststate)_\psSUBdelegator
      ) \\
      \psSUBregistrar' &= R(
        \psSUBregistrar,
        \mathbf{e}^*_\psSUBregistrar,
        (\accumulate(\psSUBregistrar)_\aoSUBpoststate)_\psSUBregistrar
      ) \\
      \psSUBstagingset' &= (
          \accumulate(\psSUBdelegator)_\aoSUBpoststate
      )_\psSUBstagingset \\
      \forall c \in \coreindex :
        \psSUBauthqueue'\sub{c} &= ((
          \accumulate(\psSUBassigners\sub{c})_\aoSUBpoststate
        )_\psSUBauthqueue)\sub{c} \\
      \mathbf{n} &= \bigcup_{s \in \mathbf{s}}(
        (\accumulate(s)_\aoSUBpoststate)_\psSUBaccounts
          \setminus
        \keys{\psSUBaccounts \setminus \set{s}}
      ) \\
      \mathbf{m} &= \bigcup_{s \in \mathbf{s}}(
        \keys{\psSUBaccounts}
          \setminus
        \keys{(\accumulate(s)_\aoSUBpoststate)_\psSUBaccounts}
      )
    \end{aligned}
  \end{aligned}}$$ $$R(o, a, b) \equiv \begin{cases}
    b &\when a = o \\
    a &\otherwise
  \end{cases}$$

And $I$ is the preimage integration function, which transforms a dictionary of service states and a set of service/blob pairs into a new dictionary of service states. Preimage provisions into services which no longer exist or whose relevant request is dropped are disregarded: $$\begin{aligned}
  I&\colon\abracegroup{
    &\tuple{\dictionary{\serviceid}{\serviceaccount}, \protoset{\tuple{\serviceid, \blob}}} \to \dictionary{\serviceid}{\serviceaccount} \\
    &\tup{\mathbf{d}, \mathbf{p}} \mapsto \mathbf{d}'\;\where \mathbf{d}' = \mathbf{d}\;\text{except:} \\
    &\quad\forall \tup{s, \mathbf{i}} \in \mathbf{p},\;
      Y(\mathbf{d}, s, \mathbf{i}):\\
    &\qquad \mathbf{d}'\subb{s}_\saSUBrequests\subb{\tup{\blake{\mathbf{i}}, \len{\mathbf{i}}}} =\sq{\thetime'}\\
    &\qquad \mathbf{d}'\subb{s}_\saSUBpreimages\subb{\blake{\mathbf{i}}} = \mathbf{i}
  } \\
  Y&\colon\abracegroup{
    &\tuple{\dictionary{\serviceid}{\serviceaccount}, \serviceid, \blob} \to \bool \\
    &\tup{\mathbf{d}, s, \mathbf{i}} \mapsto \begin{cases}
      \mathbf{d}\subb{s}_\saSUBrequests\subb{\tup{\blake{\mathbf{i}}, \len{\mathbf{i}}}} = \sq{} &\when s \in \keys{\mathbf{d}} \\
      \bot &\otherwise
    \end{cases}
  }
\end{aligned}$$

We note that while forming the union of all altered, newly added service and newly removed indices, defined in the above context as $\keys{\mathbf{n}} \cup \mathbf{m}$, different services may not each contribute the same index for a new, altered or removed service. This cannot happen for the set of removed and altered services since the code hash of removable services has no known preimage and thus cannot execute itself to make an alteration. For new services this should also never happen since new indices are explicitly selected to avoid such conflicts. In the unlikely event it does happen, the block must be considered invalid.

The single-service accumulation function, $\accone$, transforms an initial state-context, a sequence of deferred-transfers, a sequence of work-reports, a dictionary of services enjoying free accumulation (with the values indicating the amount of free gas) and a service index into an alterations state-context, a sequence of *transfers*, a possible accumulation-output, the actual PVM gas used and a set of preimage provisions. This function wrangles the work-digests of a particular service from a set of work-reports and invokes PVM execution with said data: $$\label{eq:acconeout}
  \acconeout \equiv \tuple{
    \begin{alignedat}{3}
      \isa{\aoSUBpoststate&}{\partialstate},\;
      \isa{&\aoSUBdefxfers&}{\defxfers},\;
      \isa{\aoSUByield}{\optional{\hash}},\;\\
      \isa{\aoSUBgasused&}{\gas},\;
      \isa{&\aoSUBprovisions&}{\protoset{\tuple{\serviceid, \blob}}}
    \end{alignedat}
  }$$ $$\begin{aligned}
  \label{eq:accone}
  &\accone \colon \abracegroup[\;]{
    &\begin{aligned}
      \tuple{\begin{aligned}
        &\partialstate, \defxfers, \workreports,\\
        &\dictionary{\serviceid}{\gas}, \serviceid
      \end{aligned}}
      &\to \acconeout \\
      \tup{\psX, \mathbf{t}, \mathbf{r}, \mathbf{f}, s} &\mapsto \Psi_A(\psX, \thetime', s, g, \mathbf{i}^T \!\!\concat \mathbf{i}^U)
    \end{aligned} \\
    &\text{where:} \\
    &\ \begin{aligned}
      g &= \subifnone{\mathbf{f}\sub{s}, 0}
        + \!\!\!\!\sum_{t \in \mathbf{t}, t_\dxSUBdest = s}\!\!\!\!(t_\dxSUBgas)
        + \!\!\!\!\!\!\!\!\sum_{r \in \mathbf{r}, d \in r_\wrSUBdigests, d_\wdSUBserviceindex = s}\!\!\!\!\!\!\!\!(d_\wdSUBgaslimit) \\
      \mathbf{i}^T &= \sq{\build{
        t
      }{
        t \orderedin \mathbf{t}, t_\dxSUBdest = s
      }}\\
      \mathbf{i}^U &= \sq{\build{
        \tup{\begin{alignedat}{3}
          \is{\otSUBresult}{d_\wdSUBresult},\,
          \is{\otSUBgaslimit}{d_\wdSUBgaslimit},\,
          \is{\otSUBpayloadhash}{d_\wdSUBpayloadhash},\,
          \is{&\otSUBauthtrace\;&}{r_\wrSUBauthtrace&},\\
          \is{\otSUBsegroot}{(r_\wrSUBavspec)_\asSUBsegroot},\,
          \is{\otSUBpackagehash}{(r_\wrSUBavspec)_\asSUBpackagehash},\,
          \is{&\otSUBauthorizer\;&}{r_\wrSUBauthorizer&}
        \end{alignedat}}
      }{
        \begin{alignedat}{2}
          r& \orderedin \mathbf{r},&\\
          d& \orderedin r_\wrSUBdigests,&\ d_\wdSUBserviceindex = s
        \end{alignedat}
      }}
    \end{aligned}
  }\!\!\!\!
\end{aligned}$$

This draws upon $\wdSUBgaslimit$, the gas limit implied by the selected deferred-transfers, work-reports and gas-privileges.

## Final State Integration

Given the result of the top-level $\accseq$, we may define the posterior state $\privileges'$, $\authqueue'$ and $\stagingset'$ as well as the first intermediate state of the service-accounts $\accountspostacc$ and the Accumulation Output Log $\lastaccout'$: $$\begin{aligned}
  \nonumber
  &\using g = \max\left(
    \Cblockaccgas,
    \Creportaccgas \cdot \Ccorecount + \textstyle \sum_{x \in \values{\alwaysaccers}}(x)
  \right)\\
  \nonumber
  &\also \psX = \tup{
    \is{\psSUBaccounts}{\accountspre},
    \is{\psSUBstagingset}{\stagingset},
    \is{\psSUBauthqueue}{\authqueue},
    \is{\psSUBmanager}{\manager},
    \is{\psSUBassigners}{\assigners},
    \is{\psSUBdelegator}{\delegator},
    \is{\psSUBregistrar}{\registrar},
    \is{\psSUBalwaysaccers}{\alwaysaccers}
  }
  \!\!\!\!\!\\
  \label{eq:finalstateaccumulation}
  &\tup{
    n, \psX', \mathbf{b}, \mathbf{u}
  } \equiv \accseq(g, \sq{}, \justbecameavailable^*, \psX, \alwaysaccers) \\
  &\lastaccout' \equiv \sq{\tup{s, h} \in \mathbf{b}} \\
  \label{eq:accountspostaccdef}
  &\tup{
    \is\psSUBaccounts{\accountspostacc},
    \is\psSUBstagingset{\stagingset'},
    \is\psSUBauthqueue{\authqueue'},
    \is\psSUBmanager{\manager'},
    \is\psSUBassigners{\assigners'},
    \is\psSUBdelegator{\delegator'},
    \is\psSUBregistrar{\registrar'},
    \is\psSUBalwaysaccers{\alwaysaccers'}
  } \equiv \psX'
  \!\!\!\!\!
\end{aligned}$$

From this formulation, we also receive $n$, the total number of work-reports accumulated and $\mathbf{u}$, the gas used in the accumulation process for each service. We compose $\accumulationstatistics$, our accumulation statistics, which is a mapping from the service indices which were accumulated to the amount of gas used throughout accumulation and the number of work-items accumulated. Formally: $$\begin{aligned}
  \label{eq:accumulationstatisticsspec}
  &\accumulationstatistics \in \dictionary{\serviceid}{\tuple{\gas, \N}} \\
  \label{eq:accumulationstatisticsdef}
  &\textstyle \accumulationstatistics \equiv \set{\build{
    \kv{s}{\tup{G(s), N(s)}}
  }{
    G(s) + N(s) \ne 0
  }}
  \!\!\!\!\\
  \nonumber
  \where &G(s) \equiv \sum_{\tup{s, u} \in \mathbf{u}}(u) \\
  \nonumber
  \also &N(s) \equiv \len{\sq{\build{d}{
    r \orderedin \justbecameavailable^*\sub{\dots n} ,
    d \orderedin r_\wrSUBdigests ,
    d_\wdSUBserviceindex = s
  }}}
\end{aligned}$$

The second intermediate state $\accountspostxfer$ may then be defined with the last-accumulation record being updated for all accumulated services: $$\begin{aligned}
  \accountspostxfer &\equiv \set{ \build{ \kv{s}{a'} }{ \kv{s}{a} \in \accountspostacc }} \\
  &\where a' = \begin{cases}
    a \exc a'_\saSUBlastacc = \thetime' &\when s \in \keys{\accumulationstatistics} \\
    a &\otherwise
  \end{cases}
\end{aligned}$$

We define the final state of the ready queue and the accumulated map by integrating those work-reports which were accumulated in this block and shifting any from the prior state with the oldest such items being dropped entirely: $$\begin{aligned}
  \accumulated'_{\Cepochlen - 1} &= P(\justbecameavailable^*\sub{\dots n}) \\
  \forall i \in \Nmax{\Cepochlen - 1}: \accumulated'\sub{i} &\equiv \accumulated\sub{i + 1} \\
  \forall i \in \N_\Cepochlen : \cyclic{\ready'}\sub{m - i} &\equiv \begin{cases}
    E(\justbecameavailable^Q, \accumulated'\sub{\Cepochlen - 1}) &\when i = 0 \\
    \sq{} &\when 1 \le i < \thetime' - \thetime \\
    E(\cyclic{\ready}\sub{m - i}, \accumulated'\sub{\Cepochlen - 1}) &\when i \ge \thetime' - \thetime
  \end{cases}
  \!\!\!\!
\end{aligned}$$

## Preimage Integration

After accumulation, we must integrate all preimages provided in the lookup extrinsic to arrive at the posterior account state. The lookup extrinsic is a sequence of pairs of service indices and data. These pairs must be ordered and without duplicates (equation eq:preimagesareordered requires this). The data must have been solicited by a service but not yet provided in the *prior* state. Formally: $$\begin{aligned}
  \xtpreimages &\in \sequence{\tuple{ \serviceid,\, \blob }} \\
  \label{eq:preimagesareordered}\xtpreimages &= \sqorderuniqby{i}{i \in \xtpreimages} \\
  \forall \tup{\xpSUBserviceindex, \xpSUBdata} &\in \xtpreimages : Y(\accountspre, \xpSUBserviceindex, \xpSUBdata)
\end{aligned}$$

We disregard, without prejudice, any preimages which due to the effects of accumulation are no longer useful. We define $\accountspostpreimage$ as the state after the integration of the still-relevant preimages: $$\accountspostpreimage = I(\accountspostxfer, \xtpreimages)$$

# Statistics

## Validator Activity

The chain does not explicitly issue rewards—we leave this as a job to be done by the staking subsystem (in Polkadot’s case envisioned as a system parachain—hosted without fees—in the current imagining of a public network). However, much as with validator punishment information, it is important for the chain to facilitate the arrival of information on validator activity in to the staking subsystem so that it may be acted upon.

Such performance information cannot directly cover all aspects of validator activity; whereas block production, guarantor reports and availability assurance can easily be tracked on-chain, GRANDPA, BEEFY and auditing activity cannot. In the latter case, this is instead tracked with validator voting activity: validators vote on their impression of each other’s efforts and a median may be accepted as the truth for any given validator. With an assumption of 50% honest validators, this gives an adequate means of oraclizing this information.

The validator statistics are made on a per-epoch basis and we retain one record of completed statistics together with one record which serves as an accumulator for the present epoch. Both are tracked in $\activity$, which is thus a sequence of two elements, with the first being the accumulator and the second the previous epoch’s statistics. For each epoch we track a performance record for each validator: $$\begin{aligned}
\label{eq:activityspec}
  \activity &\equiv \tup{\valstatsaccumulator, \valstatsprevious, \corestats, \servicestats}\\
  \tuple{\valstatsaccumulator, \valstatsprevious} &\in \sequence[\Cvalcount]{\tuple{
    \isa{\vsSUBblocks}{\N}\,,
    \isa{\vsSUBtickets}{\N}\,,
    \isa{\vsSUBpreimagecount}{\N}\,,
    \isa{\vsSUBpreimagesize}{\N}\,,
    \isa{\vsSUBguarantees}{\N}\,,
    \isa{\vsSUBassurances}{\N}
%    \isa{\mathbf{u}}{\sequence[\Cvalcount]{\N}}
  }}^2
  \!\!\!\!\!\!\!\!\!\!
\end{aligned}$$

The six validator statistics we track are:

$\vsSUBblocks$  
The number of blocks produced by the validator.

$\vsSUBtickets$  
The number of tickets introduced by the validator.

$\vsSUBpreimagecount$  
The number of preimages introduced by the validator.

$\vsSUBpreimagesize$  
The total number of octets across all preimages introduced by the validator.

$\vsSUBguarantees$  
The number of reports guaranteed by the validator.

$\vsSUBassurances$  
The number of availability assurances made by the validator.

The objective statistics are updated in line with their description, formally: $$\begin{aligned}
  \using e =\; &\ffrac{\thetime}{\Cepochlen} \ ,\quad e' = \ffrac{\thetime'}{\Cepochlen}\\
  \!\tup{\mathbf{a}, \valstatsprevious'} \equiv\;&\begin{cases}
      \tup{\valstatsaccumulator, \valstatsprevious} &\when e' = e \\
      \tup{\sq{\tup{0, \dots, \sq{0, \dots}}, \dots}, \valstatsaccumulator}\!\!\!\! &\otherwise
  \end{cases}\!\!\!\!\\
  \forall v \in \valindex :&\; \abracegroup{
    \valstatsaccumulator'\subb{v}_\vsSUBblocks &\equiv
      \mathbf{a}\subb{v}_\vsSUBblocks + (v = \H_\SUBauthorindex)\\
    \valstatsaccumulator'\subb{v}_\vsSUBtickets &\equiv
      \mathbf{a}\subb{v}_\vsSUBtickets + \begin{cases}
        \len{\xttickets} &\when v = \H_\SUBauthorindex \\
        0 &\otherwise
      \end{cases}\\
    \valstatsaccumulator'\subb{v}_\vsSUBpreimagecount &\equiv
      \mathbf{a}\subb{v}_\vsSUBpreimagecount + \begin{cases}
        \len{\xtpreimages} &\when v = \H_\SUBauthorindex \\
        0 &\otherwise
      \end{cases}\\
    \valstatsaccumulator'\subb{v}_\vsSUBpreimagesize &\equiv
      \mathbf{a}\subb{v}_\vsSUBpreimagesize + \begin{cases}
        \sum_{d \in \xtpreimages}\len{d} &\when v = \H_\SUBauthorindex \\
        0 &\otherwise
      \end{cases}\\
    \valstatsaccumulator'\subb{v}_\vsSUBguarantees &\equiv
      \mathbf{a}\subb{v}_\vsSUBguarantees + (\activeset'\sub{v} \in \reporters)\\
    \valstatsaccumulator'\subb{v}_\vsSUBassurances &\equiv
      \mathbf{a}\subb{v}_\vsSUBassurances +
        (\exists a \in \xtassurances : a_\xaSUBassurer = v)
  }\!\!\!\!\!
\end{aligned}$$

Note that $\reporters$ is the *Reporters* set, as defined in equation eq:guarantorsig.

## Cores and Services

The other two components of statistics are the core and service activity statistics. These are tracked only on a per-block basis unlike the validator statistics which are tracked over the whole epoch. $$\begin{aligned}
  \corestats &\in \sequence[\Ccorecount]{\tuple{
    \begin{alignedat}{7}
      \isa{\csSUBdaload&}{\N}\,,\;
      \isa{&\csSUBpopularity&}{\N}\,,\;
      \isa{&\csSUBimportcount&}{\N}\,,\;
      \isa{&\csSUBxtcount&}{\N}\,,\;\\
      \isa{\csSUBxtsize&}{\N}\,,\;
      \isa{&\csSUBexportcount&}{\N}\,,\;
      \isa{&\csSUBbundlelen&}{\N}\,,\;
      \isa{&\csSUBgasused&}{\gas}
    \end{alignedat}
  }}\\
  \servicestats &\in \dictionary{\serviceid}{\tuple{
    \begin{alignedat}{3}
      \isa{\ssSUBprovision&}{\tup{\N, \N}}\,,\;
      \isa{&\ssSUBrefinement&}{\tup{\N, \gas}}\,,\;\\
      \isa{\ssSUBimportcount&}{\N}\,,\;
      \isa{\ssSUBxtcount}{\N}\,,\;
      \isa{&\ssSUBxtsize&}{\N}\,,\;
      \isa{\ssSUBexportcount}{\N}\,,\;\\
      \isa{\ssSUBaccumulation&}{\tup{\N, \gas}}
    \end{alignedat}
  }}
\end{aligned}$$

The core statistics are updated using several intermediate values from across the overall state-transition function; $\incomingreports$, the incoming work-reports, as defined in eq:incomingworkreports and $\justbecameavailable$, the newly available work-reports, as defined in eq:availableworkreports. We define the statistics as follows: $$\begin{aligned}
  \forall c \in \coreindex : \corestats'\subb{c} &\equiv \tup{
    \begin{alignedat}{5}
      \is{\csSUBimportcount&}{R(c)_\SUBimportcount}\,,\;
      \is{&\csSUBxtcount&}{R(c)_\SUBxtcount}\,,\;
      \is{&\csSUBxtsize&}{R(c)_\SUBxtsize}\,,\\
      \is{\csSUBexportcount&}{R(c)_\SUBexportcount}\,,\;
      \is{&\csSUBgasused&}{R(c)_\SUBgasused}\,,\;
      \is{&\csSUBbundlelen&}{L(c)}\,,\\
      \is{\csSUBdaload&}{D(c)}\,,\;
      \is{&\csSUBpopularity&}{\span\span \textstyle \sum_{a \in \xtassurances} a_\xaSUBavailabilities\subb{c}\qquad}
    \end{alignedat}
  }\!\!\!\!\\
  \where R(c \in \coreindex) &\equiv
    \!\!\!\!\!\!\!\!\!\!\!
    \sum_{\wdX \in \wrX_\wrSUBdigests, \wrX \in \incomingreports, \wrX_\wrSUBcore = c}
    \!\!\!\!\!\!\!\!\!\!\!
    \tup{
      \wdX_\SUBimportcount,
      \wdX_\SUBxtcount,
      \wdX_\SUBxtsize,
      \wdX_\SUBexportcount,
      \wdX_\SUBgasused,
    }\\
  \also L(c \in \coreindex) &\equiv
    \!\!\!\!\!\!\!
    \sum_{\wrX \in \incomingreports, \wrX_\wrSUBcore = c}
    \!\!\!\!\!\!\!
    (\wrX_\wrSUBavspec)_\asSUBbundlelen\\
  \also D(c \in \coreindex) &\equiv
    \!\!\!\!\!\!
    \sum_{\wrX \in \justbecameavailable, \wrX_\wrSUBcore = c}
    \!\!\!\!\!\!
    (\wrX_\wrSUBavspec)_\asSUBbundlelen +
    \Csegmentsize\ceil{(\wrX_\wrSUBavspec)_\asSUBsegcount\nicefrac{65}{64}}
\end{aligned}$$

Finally, the service statistics are updated using the same intermediate values as the core statistics, but with a different set of calculations: $$\begin{aligned}
  \forall s \in \mathbf{s}: \servicestats'\subb{s} &\equiv \tup{
    \begin{alignedat}{5}
      \is{\ssSUBimportcount&}{R(s)_\SUBimportcount}\,,\;
      \is{&\ssSUBxtcount&}{R(s)_\SUBxtcount}\,,\;
      \is{&\ssSUBxtsize&}{R(s)_\SUBxtsize}\,,\\
      \is{\ssSUBexportcount&}{R(s)_\SUBexportcount}\,,\;
      \is{&\ssSUBrefinement&}{\span\span\tup{R(s)_n, R(s)_\SUBgasused}}\,,\;\\
      \is{\ssSUBprovision&}{
        \span\span\textstyle
        \sum_{\tup{\xpSUBserviceindex, \xpSUBdata}\,\in \xtpreimages}\tup{1, \len{\xpSUBdata}}
      }\,,\;\\
      \is{\ssSUBaccumulation&}{
        \span\span
        \subifnone{\accumulationstatistics\subb{s}, \tup{0, 0}}
      }
    \end{alignedat}
  }\!\!\!\!\\
  \where \mathbf{s}&=
    \mathbf{s}^R\cup
    \mathbf{s}^P\cup
    \keys{\accumulationstatistics}\\
  \also \mathbf{s}^R&= \set{
    \build{\wdX_\wdSUBserviceindex}{\wdX \in \wrX_\wrSUBdigests, \wrX \in \incomingreports}
  }\\
  \also \mathbf{s}^P&= \set{
    \build{s}{\exists x: \tup{s, x} \in \xtpreimages}
  }\\
  \also R(s \in \serviceid) &\equiv
    \!\!\!\!\!\!\!\!\!\!\!
    \sum_{\wdX \in \wrX_\wrSUBdigests, \wrX \in \incomingreports, \wdX_\wdSUBserviceindex = s}
    \!\!\!\!\!\!\!\!\!\!\!
    \tup{
      \is{n}{1},
      \wdX_\wdSUBgasused,
      \wdX_\wdSUBimportcount,
      \wdX_\wdSUBxtcount,
      \wdX_\wdSUBxtsize,
      \wdX_\wdSUBexportcount
    }
\end{aligned}$$

# Work Packages and Work Reports

## Honest Behavior

We have so far specified how to recognize blocks for a correctly transitioning blockchain. Through defining the state transition function and a state Merklization function, we have also defined how to recognize a valid header. While it is not especially difficult to understand how a new block may be authored for any node which controls a key which would allow the creation of the two signatures in the header, nor indeed to fill in the other header fields, readers will note that the contents of the extrinsic remain unclear.

We define not only correct behavior through the creation of correct blocks but also *honest behavior*, which involves the node taking part in several *off-chain* activities. This does have analogous aspects within *YP* Ethereum, though it is not mentioned so explicitly in said document: the creation of blocks along with the gossiping and inclusion of transactions within those blocks would all count as off-chain activities for which honest behavior is helpful. In ’s case, honest behavior is well-defined and expected of at least $\twothirds$ of validators.

Beyond the production of blocks, incentivized honest behavior includes:

- the guaranteeing and reporting of work-packages, along with chunking and distribution of both the chunks and the work-package itself, discussed in section 15;

- assuring the availability of work-packages after being in receipt of their data;

- determining which work-reports to audit, fetching and auditing them, and creating and distributing judgments appropriately based on the outcome of the audit;

- submitting the correct amount of auditing work seen being done by other validators, discussed in section 13.

## Segments and the Manifest

Our basic erasure-coding segment size is $\Cecpiecesize = 684$ octets, derived from the fact we wish to be able to reconstruct even should almost two-thirds of our 1023 participants be malicious or incapacitated, the 16-bit Galois field on which the erasure-code is based and the desire to efficiently support encoding data of close to, but no less than, 4KB.

Work-packages are generally small to ensure guarantors need not invest a lot of bandwidth in order to discover whether they can get paid for their evaluation into a work-report. Rather than having much data inline, they instead *reference* data through commitments. The simplest commitments are extrinsic data.

Extrinsic data are blobs which are being introduced into the system alongside the work-package itself generally by the work-package builder. They are exposed to the Refine logic as an argument. We commit to them through including each of their hashes in the work-package.

Work-packages have two other types of external data associated with them: A cryptographic commitment to each *imported* segment and finally the number of segments which are *exported*.

### Segments, Imports and Exports

The ability to communicate large amounts of data from one work-package to some subsequent work-package is a key feature of the availability system. An export segment, defined as the set $\segment$, is an octet sequence of fixed length $\Csegmentsize = 4104$. It is the smallest datum which may individually be imported from—or exported to—the long-term D$^3$L during the Refine function of a work-package. Being an exact multiple of the erasure-coding piece size ensures that the data segments of work-package can be efficiently placed in the D$^3$L system. $$\label{eq:segment}
  \segment \equiv \blob[\Csegmentsize]$$

Exported segments are data which are *generated* through the execution of the Refine logic and thus are a side effect of transforming the work-package into a work-report. Since their data is deterministic based on the execution of the Refine logic, we do not require any particular commitment to them in the work-package beyond knowing how many are associated with each Refine invocation in order that we can supply an exact index.

On the other hand, imported segments are segments which were exported by previous work-packages. In order for them to be easily fetched and verified they are referenced not by hash but rather the root of a Merkle tree which includes any other segments introduced at the time, together with an index into this sequence. This allows for justifications of correctness to be generated, stored, included alongside the fetched data and verified. This is described in depth in the next section.

### Data Collection and Justification

It is the task of a guarantor to reconstitute all imported segments through fetching said segments’ erasure-coded chunks from enough unique validators. Reconstitution alone is not enough since corruption of the data would occur if one or more validators provided an incorrect chunk. For this reason we ensure that the import segment specification (a Merkle root and an index into the tree) be a kind of cryptographic commitment capable of having a justification applied to demonstrate that any particular segment is indeed correct.

Justification data must be available to any node over the course of its segment’s potential requirement. At around 350 bytes to justify a single segment, justification data is too voluminous to have all validators store all data. We therefore use the same overall availability framework for hosting justification metadata as the data itself.

The guarantor is able to use this proof to justify to themselves that they are not wasting their time on incorrect behavior. We do not force auditors to go through the same process. Instead, guarantors build an *Auditable Work Package*, and place this in the Audit DA system. This is the original work-package, its extrinsic data, its imported data and a concise proof of correctness of that imported data. This tactic routinely duplicates data between the D$^3$L and the Audit DA, however it is acceptable in order to reduce the bandwidth cost for auditors who must justify the correctness as cheaply as possible as auditing happens on average 30 times for each work-package whereas guaranteeing happens only twice or thrice.

## Packages and Items

We begin by defining a *work-package*, of set $\workpackage$, and its constituent *work-item*s, of set $\workitem$. A work-package includes a simple blob acting as an authorization token $\wpSUBauthtoken$, the index of the service which hosts the authorization code $\wpSUBauthcodehost$, an authorization code hash $\wpSUBauthcodehash$ and a configuration blob $\wpSUBauthconfig$, a context $\wpSUBcontext$ and a sequence of work items $\wpSUBworkitems$: $$\label{eq:workpackage}
  \workpackage \equiv \tuple{
    \isa{\wpSUBauthtoken}{\blob},\ 
    \isa{\wpSUBauthcodehost}{\serviceid},\ 
    \isa{\wpSUBauthcodehash}{\hash},\ 
    \isa{\wpSUBauthconfig}{\blob},\ 
    \isa{\wpSUBcontext}{\workcontext},\ 
    \isa{\wpSUBworkitems}{\sequence[1:\Cmaxpackageitems]{\workitem}}
  }$$

A work item includes: $\wiSUBserviceindex$ the identifier of the service to which it relates, the code hash of the service at the time of reporting $\wiSUBcodehash$ (whose preimage must be available from the perspective of the lookup anchor block), a payload blob $\wiSUBpayload$, gas limits for Refinement and Accumulation $\wiSUBrefgaslimit$ & $\wiSUBaccgaslimit$, and the three elements of its manifest, a sequence of imported data segments $\wiSUBimportsegments$ which identify a prior exported segment through an index and the identity of an exporting work-package, $\wiSUBextrinsics$, a sequence of blob hashes and lengths to be introduced in this block (and which we assume the validator knows) and $\wiSUBexportcount$ the number of data segments exported by this work item. $$\label{eq:workitem}
  \workitem \equiv \tuple{\begin{aligned}
    &\isa{\wiSUBserviceindex}{\serviceid},
    \isa{\wiSUBcodehash}{\hash},
    \isa{\wiSUBpayload}{\blob},
    \isa{\wiSUBrefgaslimit}{\gas},
    \isa{\wiSUBaccgaslimit}{\gas},
    \isa{\wiSUBexportcount}{\N}, \\
    &\isa{\wiSUBimportsegments}{\sequence{\tuple{\hash \cup (\hash^\boxplus),\N}}},
    \isa{\wiSUBextrinsics}{\sequence{\tuple{\hash, \N}}}
  \end{aligned}}$$

Note that an imported data segment’s work-package is identified through the union of sets $\hash$ and a tagged variant $\hash^\boxplus$. A value drawn from the regular $\hash$ implies the hash value is of the segment-root containing the export, whereas a value drawn from $\hash^\boxplus$ implies the hash value is the hash of the exporting work-package. In the latter case it must be converted into a segment-root by the guarantor and this conversion reported in the work-report for on-chain validation.

We limit the total number of exported items to $\Cmaxpackageexports = 3072$, the total number of imported items to $\Cmaxpackageimports = 3072$, and the total number of extrinsics to $\Cmaxpackagexts = 128$: $$\label{eq:limitworkpackagebandwidth}
  \!\!\!\!
  \begin{aligned}
    &\forall \wpX \in \workpackage: \\
    &\ \sum_{\wiX \in \wpX_\wpSUBworkitems} \wiX_\wiSUBexportcount \le \Cmaxpackageexports \ \wedge\ 
    \sum_{\wiX \in \wpX_\wpSUBworkitems} \len{\wiX_\wiSUBimportsegments} \le \Cmaxpackageimports \ \wedge\ 
    \sum_{\wiX \in \wpX_\wpSUBworkitems} \len{\wiX_\wiSUBextrinsics} \le \Cmaxpackagexts
  \end{aligned}$$

We make an assumption that the preimage to each extrinsic hash in each work-item is known by the guarantor. In general this data will be passed to the guarantor alongside the work-package.

We limit the total size of the auditable *work-bundle*, containing the work-package, import and extrinsic items, together with all payloads, the authorizer configuration and the authorization token to around 13.6MB. This limit allows 2MB/s/core D$^{3}$L imports, and thus a full complement of 3,072 imports, assuming no extrinsics, 64 bytes for each of the authorization token and trace, and a work-item payload of 4KB: $$\begin{aligned}
  \label{eq:checkextractsize}
  &\begin{aligned}
    &\forall \wpX \in \workpackage: \Big(\len{\wpX_\wpSUBauthtoken} + \len{\wpX_\wpSUBauthconfig} +
    \!\!\sum_{\wiX \in \wpX_\wpSUBworkitems}\!\!S(\wiX)\Big) \le \Cmaxbundlesize \\
    &\where S(\wiX \in \workitem) \equiv \len{\wiX_\wiSUBpayload} + \len{\wiX_\wiSUBimportsegments}\cdot\Csegmentfootprint + \!\!\!\!\!\!\sum_{\tup{h, l} \in \wiX_\wiSUBextrinsics} \!\!\!l
  \end{aligned}\\
  \label{eq:segmentfootprint}
  &\Csegmentfootprint \equiv \Csegmentsize + 32\ceil{\log_2(\Cmaxpackageimports)}\\
  &\Cmaxbundlesize \equiv \Cmaxpackageimports\cdot\Csegmentfootprint + 4096 + 64 + 64 = 13,791,360
\end{aligned}$$

We limit the sums of each of the two gas limits to be at most the maximum gas allocated to a core for the corresponding operation: $$\label{eq:wplimits}
  \forall \wpX \in \workpackage:\ \;
    \sum_{\wiX \in \wpX_\wpSUBworkitems}(\wiX_\wiSUBaccgaslimit) < \Creportaccgas
  \quad\wedge\ \;
    \sum_{\wiX \in \wpX_\wpSUBworkitems}(\wiX_\wiSUBrefgaslimit) < \Cpackagerefgas$$

Given the result $\wdSUBresult$ and gas used $\wdSUBgasused$ of some work-item, we define the item-to-digest function $C$ as: $$C\colon\abracegroup{
    \tuple{\workitem, \blob \cup \workerror, \gas} &\to \workdigest\\
    \tup{\tup{\begin{aligned}
      &\SUBserviceindex, \SUBcodehash, \SUBpayload,\\
      &\wiSUBaccgaslimit, \SUBexportcount, \wiSUBimportsegments, \wiSUBextrinsics
    \end{aligned}
    }, \wdSUBresult, \wdSUBgasused} &\mapsto \tup{\begin{aligned}
      &\wdSUBserviceindex,\,
      \wdSUBcodehash,\,
      \is{\wdSUBpayloadhash}{\blake{\SUBpayload}},\,
      \is{\wdSUBgaslimit}{\wiSUBaccgaslimit},\,
      \wdSUBresult,\,
      \wdSUBgasused,\\
      &\is{\wdSUBimportcount}{\len{\wiSUBimportsegments}},\,
      \wdSUBexportcount,\,
      \is{\wdSUBxtcount}{\len{\wiSUBextrinsics}},\,
      \is{\wdSUBxtsize}{\!\!\!\!\sum_{\tup{h, z} \in \wiSUBextrinsics}\!\!\!\!z}
    \end{aligned}}\!\!\!\!
  }$$

We define the work-package’s implied authorizer as $\wpX_\wpSUBauthorizer$, the hash of the authorization code hash concatenated with the configuration. We define the authorization code as $\wpX_\wpSUBauthcode$ and require that it be available at the time of the lookup anchor block from the historical lookup of service $\wpX_\wpSUBauthcodehost$. Formally: $$\forall \wpX \in \workpackage: \abracegroup[\,]{
    \wpX_\wpSUBauthorizer &\equiv \blake{\wpX_\wpSUBauthcodehash \concat \wpX_\wpSUBauthconfig} \\
    \encode{\var{\wpX_\wpSUBmetadata}, \wpX_\wpSUBauthcode} &\equiv \histlookup(\accounts\subb{\wpX_\wpSUBauthcodehost}, (\wpX_\wpSUBcontext)_\wcSUBlookupanchortime, \wpX_\wpSUBauthcodehash) \\
    \tup{\wpX_\wpSUBmetadata, \wpX_\wpSUBauthcode} &\in \tuple{\blob, \blob}
  }$$

(The historical lookup function, $\histlookup$, is defined in equation eq:historicallookup.)

### Exporting

Any of a work-package’s work-items may *export* segments and a *segments-root* is placed in the work-report committing to these, ordered according to the work-item which is exporting. It is formed as the root of a constant-depth binary Merkle tree as defined in equation eq:constantdepthmerkleroot.

Guarantors are required to erasure-code and distribute two data sets: one blob, the auditable *bundle* containing the encoded work-package, extrinsic data and self-justifying imported segments which is placed in the short-term Audit DA store; and a second set of exported-segments data together with the *Paged-Proofs* metadata. Items in the first store are short-lived; assurers are expected to keep them only until finality of the block in which the availability of the work-result’s work-package is assured. Items in the second, meanwhile, are long-lived and expected to be kept for a minimum of 28 days (672 complete epochs) following the reporting of the work-report. This latter store is referred to as the *Distributed, Decentralized, Data Lake* or D$^3$L owing to its large size.

We define the paged-proofs function $P$ which accepts a series of exported segments $\mathbf{s}$ and defines some series of additional segments placed into the D$^3$L via erasure-coding and distribution. The function evaluates to pages of hashes, together with subtree proofs, such that justifications of correctness based on a segments-root may be made from it: $$\label{eq:pagedproofs}
  \!\!P\colon\abracegroup{
    \sequence{\segment} \to \,&\sequence{\segment} \\
    \mathbf{s} \mapsto \,&\sq{\build{
      \zeropad{l}{\encode{
        \var{\merklejustsubpath{6}{\mathbf{s}, i}},
        \var{\merklesubtreepage{6}{\mathbf{s}, i}}
      }}
    }{
      i \orderedin \Nmax{\ceil{\nicefrac{\len{\mathbf{s}}}{64}}}
    }} \\
    & \where l = \Csegmentsize
  }\!\!\!\!$$

## Computation of Work-Report

We now come to the work-report computation function $\computereport$. This forms the basis for all utilization of cores on . It accepts some work-package $\wpX$ for some nominated core $\SUBcore$ and results in either an error $\error$ or the work-report and series of exported segments. This function is deterministic and requires only that it be evaluated within eight epochs of a recently finalized block thanks to the historical lookup functionality. It can thus comfortably be evaluated by any node within the auditing period, even allowing for practicalities of imperfect synchronization. Formally: $$\label{eq:workdigestfunction}
  \computereport \colon \abracegroup{
    \tuple{\workpackage, \coreindex} &\to \workreport \\
    \tup{\wpX, \SUBcore} &\mapsto \begin{cases}
      \error &\when \wrSUBauthtrace \not\in \blob[:\Cmaxreportvarsize] \\
      \tup{\wrSUBavspec, \is{\wrSUBcontext}{\wpX_\wpSUBcontext}, \SUBcore, \is{\wrSUBauthorizer}{\wpX_\wpSUBauthorizer}, \wrSUBauthtrace, \wrSUBsrlookup, \wrSUBdigests, \wrSUBauthgasused} &\otherwise
    \end{cases}
  }$$

Where: $$\begin{aligned}
  \keys{\wrSUBsrlookup} \equiv \,&\set{\build{h}{\wiX \in \wpX_\wpSUBworkitems, \tup{h^\boxplus, n} \in \wiX_\wiSUBimportsegments}} \ ,\quad\len{\wrSUBsrlookup} \le 8\\
  \tup{\wrSUBauthtrace, \wrSUBauthgasused} = \,&\Psi_I(\wpX, \SUBcore) \\
  \tup{\wrSUBdigests, \overline{\mathbf{e}}} = \,&\transpose \sq{\build{
    (C(\wpX_\wpSUBworkitems\subb{j}, r, u), \mathbf{e})
  }{
    \tup{r, u, \mathbf{e}} = I(\wpX, j),\,
    j \orderedin \Nmax{\len{\wpX_\wpSUBworkitems}}
  }} \\
  I(\wpX, j) \equiv \,&\begin{cases}
    \tup{\oversize, u, \sq{\segment_0, \segment_0, \dots}\interval{}{m_\wiSUBexportcount}} &\when \len{r} + z > \Cmaxreportvarsize\\
    \tup{\badexports, u, \sq{\segment_0, \segment_0, \dots}\interval{}{m_\wiSUBexportcount}} &\otherwhen \len{\mathbf{e}} \ne m_\wiSUBexportcount \\
    \tup{r, u, \sq{\segment_0, \segment_0, \dots}\interval{}{m_\wiSUBexportcount}} &\otherwhen r \not\in \blob \\
    \tup{r, u, \mathbf{e}} &\otherwise \\
    \multicolumn{2}{l}{\where \tup{r, \mathbf{e}, u} = \Psi_R(
      c, j, \wpX, \mathbf{o}, S^\#(\wpX_\wpSUBworkitems), \ell
    )}\\
    \multicolumn{2}{l}{\also h = \blake{\wpX}\,,\; m= \wpX_\wpSUBworkitems\subb{j}\,,\; \ell = \sum_{k < j}\wpX_\wpSUBworkitems\subb{k}_\wiSUBexportcount}\\
    \multicolumn{2}{l}{\also z = \len{\mathbf{o}} + \sum_{k < j, \tup{r \in \blob, \dots} = I(\wpX, k)} \len{r}}
  \end{cases}
\end{aligned}$$

Note that we gracefully handle both the case where the output size of the work output would take the work-report beyond its acceptable size and where number of segments exported by a work-item’s Refinement execution is incorrectly reported in the work-item’s export segment count. In both cases, the work-package continues to be valid as a whole, but the work-item’s exported segments are replaced by a sequence of zero-segments equal in size to the export segment count and its output is replaced by an error.

Initially we constrain the segment-root dictionary $\wrSUBsrlookup$: It should contain entries for all unique work-package hashes of imported segments not identified directly via a segment-root but rather through a work-package hash.

We immediately define the segment-root lookup function $L$, dependent on this dictionary, which collapses a union of segment-roots and work-package hashes into segment-roots using the dictionary: $$L(r \in \hash \cup \hash^\boxplus) \equiv \begin{cases}
    r &\when r \in \hash \\
    \wrSUBsrlookup\subb{h} &\when \exists h \in \hash: r = h^\boxplus
  \end{cases}$$

In order to expect to be compensated for a work-report they are building, guarantors must compose a value for $\wrSUBsrlookup$ to ensure not only the above but also a further constraint that all pairs of work-package hashes and segment-roots do properly correspond: $$\forall \kv{h}{e} \in \wrSUBsrlookup : \exists \wpX, \SUBcore \in \workpackage, \coreindex : \blake{\wpX} = h \wedge (\computereport(\wpX, \SUBcore)_\wrSUBavspec)_\asSUBsegroot = e
  \!\!\!\!$$

As long as the guarantor is unable to satisfy the above constraints, then it should consider the work-package unable to be guaranteed. Auditors are not expected to populate this but rather to reuse the value in the work-report they are auditing.

The next term to be introduced, $\tup{\wrSUBauthtrace, \wrSUBauthgasused}$, is the authorization trace, the result of the Is-Authorized function together with the amount of gas it used. The second term, $\tup{\wrSUBdigests, \overline{\mathbf{e}}}$ is the sequence of results for each of the work-items in the work-package together with all segments exported by each work-item. The third definition $I$ performs an ordered accumulation (counter) in order to ensure that the Refine function has access to the total number of exports made from the work-package up to the current work-item.

The above relies on two functions, $S$ and $X$ which, respectively, define the import segment data and the extrinsic data for some work-item argument $\wiX$. We also define $J$, which compiles justifications of segment data: $$\begin{aligned}
    X(\wiX \in \workitem) &\equiv \sq{\build{\mathbf{d}}{(\blake{\mathbf{d}}, \len{\mathbf{d}}) \orderedin \wiX_\wiSUBextrinsics}} \\
    S(\wiX \in \workitem) &\equiv \sq{\build{\mathbf{b}\subb{n}}{\merklizecd{\mathbf{b}} = L(r), \tup{r, n} \orderedin \wiX_\wiSUBimportsegments}} \\
    J(\wiX \in \workitem) &\equiv \sq{\build{\var{\merklejustsubpath{0}{\mathbf{b}, n}}}{\merklizecd{\mathbf{b}} = L(r), \tup{r, n} \orderedin \wiX_\wiSUBimportsegments}}
  \end{aligned}$$

We may then define $\wrSUBavspec$ as the data availability specification of the package using these three functions together with the yet to be defined *Availability Specifier* function $A$ (see section 14.4.1): $$\wrSUBavspec = A(
    \blake{\wpX},
    \encode{
      \wpX,
      X^\#(\wpX_\wpSUBworkitems),
      S^\#(\wpX_\wpSUBworkitems),
      J^\#(\wpX_\wpSUBworkitems)
    },
    \concatall{\overline{\mathbf{e}}}
  )\!\!\!\!$$

Note that while the formulations of $S$ and $J$ seem to require (due to the inner term $\mathbf{b}$) all segments exported by all work-packages exporting a segment to be imported, such a vast amount of data is not generally needed. In particular, each justification can be derived through a single paged-proof. This reduces the worst case data fetching for a guarantor to two segments for every one to be imported. In the case that contiguously exported segments are imported (which we might assume is a fairly common situation), then a single proof-page should be sufficient to justify many imported segments.

Also of note is the lack of length prefixes: only the Merkle paths for the justifications have a length prefix. All other sequence lengths are determinable through the work package itself.

The Is-Authorized logic it references must be executed first in order to ensure that the work-package warrants the needed core-time. Next, the guarantor should ensure that all segment-tree roots which form imported segment commitments are known and have not expired. Finally, the guarantor should ensure that they can fetch all preimage data referenced as the commitments of extrinsic segments.

Once done, then imported segments must be reconstructed. This process may in fact be lazy as the Refine function makes no usage of the data until the *fetch* host-call is made. Fetching generally implies that, for each imported segment, erasure-coded chunks are retrieved from enough unique validators (342, including the guarantor) and is described in more depth in appendix 30. (Since we specify systematic erasure-coding, its reconstruction is trivial in the case that the correct 342 validators are responsive.) Chunks must be fetched for both the data itself and for justification metadata which allows us to ensure that the data is correct.

Validators, in their role as availability assurers, should index such chunks according to the index of the segments-tree whose reconstruction they facilitate. Since the data for segment chunks is so small at 12 octets, fixed communications costs should be kept to a bare minimum. A good network protocol (out of scope at present) will allow guarantors to specify only the segments-tree root and index together with a Boolean to indicate whether the proof chunk need be supplied. Since we assume at least 341 other validators are online and benevolent, we can assume that the guarantor can compute $S$ and $J$ above with confidence, based on the general availability of data committed to with $\mathbf{s}^\clubsuit$, which is specified below.

### Availability Specifier

We define the availability specifier function $A$, which creates an availability specifier from the package hash, an octet sequence of the audit-friendly work-package bundle (comprising the work-package itself, the extrinsic data and the concatenated import segments along with their proofs of correctness), and the sequence of exported segments: $$\!\!\!
  A\colon\abracegroup[\,]{
    \tuple{\hash, \blob, \sequence{\segment}} &\to \avspec\\
    \tup{\asSUBpackagehash, \mathbf{b},\,\mathbf{s}} &\mapsto \tup{
      \asSUBpackagehash,\,
      \is{\asSUBbundlelen}{\len{\mathbf{b}}},\,
      \asSUBerasureroot,\,
      \is{\asSUBsegroot}{\merklizecd{\mathbf{s}}},\,
      \is{\asSUBsegcount}{\len{\mathbf{s}}}
    }
  }\!\!\!\!\!$$ $$\begin{aligned}
  \where \asSUBerasureroot &= \merklizewb{
    \sq{\build{\concatall{\mathbf{x}}}{\mathbf{x} \orderedin \transpose \sq{\mathbf{b}^\clubsuit, \mathbf{s}^\clubsuit}}}
  }\\
  \also \mathbf{b}^\clubsuit &= \blakemany{\erasurecode[\ceil{\nicefrac{\len{\mathbf{b}}}{\Cecpiecesize}}]{\zeropad{\Cecpiecesize}{\mathbf{b}}}}\\
  \also \mathbf{s}^\clubsuit &= \merklizewbmany{\transpose\erasurecodemany[6]{\mathbf{s} \concat P(\mathbf{s})}}
\end{aligned}$$

The paged-proofs function $P$, defined earlier in equation eq:pagedproofs, accepts a sequence of segments and returns a sequence of paged-proofs sufficient to justify the correctness of every segment. There are exactly $\ceil{\nicefrac{1}{64}}$ paged-proof segments as the number of yielded segments, each composed of a page of 64 hashes of segments, together with a Merkle proof from the root to the subtree-root which includes those 64 segments.

The functions $\fnmerklizecd$ and $\fnmerklizewb$ are the fixed-depth and simple binary Merkle root functions, defined in equations eq:constantdepthmerkleroot and eq:simplemerkleroot. The function $\fnerasurecode$ is the erasure-coding function, defined in appendix 30.

And $\fnzeropad{}$ is the zero-padding function to take an octet array to some multiple of $n$ in length: $$\label{eq:zeropadding}
  \fnzeropad{n \in \Nclamp{1}{}}\colon\abracegroup{
    \blob &\to \blob[k \cdot n]\\
    \mathbf{x} &\mapsto \mathbf{x} \concat \sq{0, 0, \dots}\interval{((\len{x} + n - 1) \bmod n) + 1}{n}
  }$$

Validators are incentivized to distribute each newly erasure-coded data chunk to the relevant validator, since they are not paid for guaranteeing unless a work-report is considered to be *available* by a super-majority of validators. Given our work-package $\mathbf{p}$, we should therefore send the corresponding work-package bundle chunk and exported segments chunks to each validator whose keys are together with similarly corresponding chunks for imported, extrinsic and exported segments data, such that each validator can justify completeness according to the work-report’s *erasure-root*. In the case of a coming epoch change, they may also maximize expected reward by distributing to the new validator set.

We will see this function utilized in the next sections, for guaranteeing, auditing and judging.

# Guaranteeing

Guaranteeing work-packages involves the creation and distribution of a corresponding *work-report* which requires certain conditions to be met. Along with the report, a signature demonstrating the validator’s commitment to its correctness is needed. With two guarantor signatures, the work-report may be distributed to the forthcoming chain block author in order to be used in the $\xtguarantees$, which leads to a reward for the guarantors.

We presume that in a public system, validators will be punished severely if they malfunction and commit to a report which does not faithfully represent the result of $\computereport$ applied on a work-package. Overall, the process is:

1.  Evaluation of the work-package’s authorization, and cross-referencing against the authorization pool in the most recent chain state.

2.  Creation and publication of a work-package report.

3.  Chunking of the work-package and each of its extrinsic and exported data, according to the erasure codec.

4.  Distributing the aforementioned chunks across the validator set.

5.  Providing the work-package, extrinsic and exported data to other validators on request is also helpful for optimal network performance.

For any work-package $p$ we are in receipt of, we may determine the work-report, if any, it corresponds to for the core $c$ that we are assigned to. When chain state is needed, we always utilize the chain state of the most recent block.

For any guarantor of index $v$ assigned to core $c$ and a work-package $p$, we define the work-report $r$ simply as: $$r = \computereport(p, c)$$

Such guarantors may safely create and distribute the payload $\tup{s, v}$. The component $s$ may be created according to equation eq:guarantorsig; specifically it is a signature using the validator’s registered Ed25519 key on a payload $l$: $$l = \blake{\encode{r}}$$

To maximize profit, the guarantor should require the work-digest meets all expectations which are in place during the guarantee extrinsic described in section 11.4. This includes contextual validity and inclusion of the authorization in the authorization pool. No doing so does not result in punishment, but will prevent the block author from including the package and so reduces rewards.

Advanced nodes may maximize the likelihood that their reports will be includable on-chain by attempting to predict the state of the chain at the time that the report will get to the block author. Naive nodes may simply use the current chain head when verifying the work-report. To minimize work done, nodes should make all such evaluations *prior* to evaluating the $\Psi_R$ function to calculate the report’s work-results.

Once evaluated as a reasonable work-package to guarantee, guarantors should maximize the chance that their work is not wasted by attempting to form consensus over the core. To achieve this they should send the work-package to any other guarantors on the same core which they do not believe already know of it.

In order to minimize the work for block authors and thus maximize expected profits, guarantors should attempt to construct their core’s next guarantee extrinsic from the work-report, core index and set of attestations including their own and as many others as possible.

In order to minimize the chance of any block authors disregarding the guarantor for anti-spam measures, guarantors should sign an average of no more than two work-reports per timeslot.

# Availability Assurance

Validators should issue a signed statement, called an *assurance*, when they are in possession of all of their corresponding erasure-coded chunks for a given work-report which is currently pending availability. For any work-report to gain an assurance, there are two classes of data a validator must have:

Firstly, their erasure-coded chunk for this report’s bundle. The validity of this chunk can be trivially proven through the work-report’s work-package erasure-root and a Merkle-proof of inclusion in the correct location. The proof should be included from the guarantor. This chunk is needed to verify the work-report’s validity and completeness and need not be retained after the work-report is considered audited. Until then, it should be provided on request to validators.

Secondly, the validator should have in hand the corresponding erasure-coded chunk for each of the exported segments referenced by the *segments root*. These should be retained for 28 days and provided to any validator on request.

# Auditing and Judging

The auditing and judging system is theoretically equivalent to that in ELVES, introduced by . For a full security analysis of the mechanism, see this work. There is a difference in terminology, where the terms *backing*, *approval* and *inclusion* there refer to our guaranteeing, auditing and accumulation, respectively.

## Overview

The auditing process involves each node requiring themselves to fetch, evaluate and issue judgment on a random but deterministic set of work-reports from each chain block in which the work-report becomes available (from $\justbecameavailable$). Prior to any evaluation, a node declares and proves its requirement. At specific common junctures in time thereafter, the set of work-reports which a node requires itself to evaluate from each block’s $\justbecameavailable$ may be enlarged if any declared intentions are not matched by a positive judgment in a reasonable time or in the event of a negative judgment being seen. These enlargement events are called tranches.

If all declared intentions for a work-report are matched by a positive judgment at any given juncture, then the work-report is considered *audited*. Once all of any given block’s newly available work-reports are audited, then we consider the block to be *audited*. One prerequisite of a node finalizing a block is for it to view the block as audited. Note that while there will be eventual consensus on whether a block is audited, there may not be consensus at the time that the block gets finalized. This does not affect the crypto-economic guarantees of this system.

In regular operation, no negative judgments will ultimately be found for a work-report, and there will be no direct consequences of the auditing stage. In the unlikely event that a negative judgment is found, then one of several things happens; if there are still more than $\twothirds\Cvalcount$ positive judgments, then validators issuing negative judgments may receive a punishment for time-wasting. If there are greater than $\onethird\Cvalcount$ negative judgments, then the block which includes the work-report is ban-listed. It and all its descendants are disregarded and may not be built on. In all cases, once there are enough votes, a judgment extrinsic can be constructed by a block author and placed on-chain to denote the outcome. See section 10 for details on this.

All announcements and judgments are published to all validators along with metadata describing the signed material. On receipt of sure data, validators are expected to update their perspective accordingly (later defined as $J$ and $A$).

## Data Fetching

For each work-report to be audited, we use its erasure-root to request erasure-coded chunks from enough assurers. From each assurer we fetch three items (which with a good network protocol should be done under a single request) corresponding to the work-package super-chunks, the self-justifying imports super-chunks and the extrinsic segments super-chunks.

We may validate the work-package reconstruction by ensuring its hash is equivalent to the hash includes as part of the work-package specification in the work-report. We may validate the extrinsic segments through ensuring their hashes are each equivalent to those found in the relevant work-item.

Finally, we may validate each imported segment as a justification must follow the concatenated segments which allows verification that each segment’s hash is included in the referencing Merkle root and index of the corresponding work-item.

Exported segments need not be reconstructed in the same way, but rather should be determined in the same manner as with guaranteeing, through the execution of the Refine logic.

All items in the work-package specification field of the work-report should be recalculated from this now known-good data and verified, essentially retracing the guarantors steps and ensuring correctness.

## Selection of Reports

Each validator shall perform auditing duties on each valid block received. Since we are entering off-chain logic, and we cannot assume consensus, we henceforth consider ourselves a specific validator of index $v$ and assume ourselves focused on some recent block $\block$ with other terms corresponding to the state-transition implied by that block, so $\reports$ is said block’s prior core-allocation, $\activeset$ is its prior validator set, $\header$ is its header Practically, all considerations must be replicated for all blocks and multiple blocks’ considerations may be underway simultaneously.

We define the sequence of work-reports which we may be required to audit as $\mathbf{q}$, a sequence of length equal to the number of cores, which functions as a mapping of core index to a work-report pending which has just become available, or $\none$ if no report became available on the core. Formally: $$\begin{aligned}
\label{eq:auditselection}
  \mathbf{q}&\in \sequence[\Ccorecount]{\optional{\workreport}} \\
  \mathbf{q}&\equiv \sq{\build{
    \begin{rcases}
      \reports\subb{\cX}_\rsSUBworkreport &\when \reports\subb{\cX}_\rsSUBworkreport \in \justbecameavailable \\
      \none &\otherwise
    \end{rcases}
  }{
    \cX \orderedin \coreindex
  }}
\end{aligned}$$

We define our initial audit tranche in terms of a verifiable random quantity $s\sub{0}$ created specifically for it: $$\begin{aligned}
  \label{eq:initialaudit}
  s\sub{0} &\in \bssignature{
    \activeset\subb{v}_\vkSUBbs
  }{
    \Xaudit \concat \banderout{\H_\SUBvrfsig}
  }{
    \sq{}
  } \\
  \Xaudit &= \token{\$jam\_audit}
\end{aligned}$$

We may then define $\mathbf{a}\sub{0}$ as the non-empty items to audit through a verifiably random selection of ten cores: $$\begin{aligned}
  \mathbf{a}\sub{0} &= \set{\build{\wrcX}{\wrcX \in \mathbf{p}\subrange{}{10}, \wrX \ne \none}} \\
  \where \mathbf{p} &= \fyshuffle{\sq{\build{\tup{\cX, \mathbf{q}\sub{\cX}}}{\cX \orderedin \coreindex}}, \banderout{s\sub{0}}}
\end{aligned}$$

Every $\Ctrancheseconds = 8$ seconds following a new time slot, a new tranche begins, and we may determine that additional cores warrant an audit from us. Such items are defined as $\mathbf{a}\sub{n}$ where $n$ is the current tranche. Formally: $$\using n = \ffrac{\wallclock - \Cslotseconds\cdot\H_\SUBtimeslot}{\Ctrancheseconds}$$

New tranches may contain items from $\mathbf{q}$ stemming from one of two reasons: either a negative judgment has been received; or the number of judgments from the previous tranche is less than the number of announcements from said tranche. In the first case, the validator is always required to issue a judgment on the work-report. In the second case, a new special-purpose VRF must be constructed to determine if an audit and judgment is warranted from us.

In all cases, we publish a signed statement of which of the cores we believe we are required to audit (an *announcement*) together with evidence of the VRF signature to select them and the other validators’ announcements from the previous tranche unmatched with a judgment in order that all other validators are capable of verifying the announcement. *Publication of an announcement should be taken as a contract to complete the audit regardless of any future information.*

Formally, for each tranche $n$ we ensure the announcement statement is published and distributed to all other validators along with our validator index $v$, evidence $s\sub{n}$ and all signed data. Validator’s announcement statements must be in the set $S$: $$\begin{aligned}
  \label{eq:announcement}
  S &\equiv \edsignature{\activeset\subb{v}_\vkSUBed}{\Xannounce \append n \concat \mathbf{x}\sub{n} \concat \blake{\H}} \\
  \where \mathbf{x}\sub{n} &= \encode{\set{\build{\encode[2]{\cX} \concat \blake{\wrX}}{\wrcX \in \mathbf{a}\sub{n}}}}\\
  \Xannounce &= \token{\$jam\_announce}
\end{aligned}$$

We define $A\sub{n}$ as our perception of which validator is required to audit each of the work-reports (identified by their associated core) at tranche $n$. This comes from each other validators’ announcements (defined above). It cannot be correctly evaluated until $n$ is current. We have absolute knowledge about our own audit requirements. $$\begin{aligned}
  A\sub{n}: \workreport &\to \protoset{\valindex} \\
%  \forall \tup{\cX, \wrX} &\in \localSUBtranche\sub{0} : v \in q\sub{0}(\wrX)
  % TODO: #445 ^^^ Fix this.
\end{aligned}$$

We further define $J_\top$ and $J_\bot$ to be the validator indices who we know to have made respectively, positive and negative, judgments mapped from each work-report’s core. We don’t care from which tranche a judgment is made. $$\begin{aligned}
  J_\bool: \workreport \to \protoset{\valindex}
\end{aligned}$$

We are able to define $\mathbf{a}\sub{n}$ for tranches beyond the first on the basis of the number of validators who we know are required to conduct an audit yet from whom we have not yet seen a judgment. It is possible that the late arrival of information alters $\mathbf{a}\sub{n}$ and nodes should reevaluate and act accordingly should this happen.

We can thus define $\mathbf{a}\sub{n}$ beyond the initial tranche through a new VRF which acts upon the set of *no-show* validators. $$\begin{aligned}
  \nonumber\forall n > 0:&\\
  \label{eq:latertranches}
  \ s\sub{n}(\wrX) &\in \bssignature{\activeset\subb{v}_\vkSUBbs}{\Xaudit \concat \banderout{\H_\SUBvrfsig}\concat\blake{\wrX}\append n}{\sq{}} \\
  \ \mathbf{a}\sub{n} &\equiv \set{ \build{ \wrX }{\textstyle\frac{\Cvalcount}{256\Cauditbiasfactor}\banderout{s\sub{n}(\wrX)}\sub{0} < m\sub{n}, \wrX \in \mathbf{q}, \wrX \ne \none }}\!\!\!\!\\
  \nonumber \where m\sub{n} &= \len{A_{n - 1}(\wrX) \setminus J_\top(\wrX)}
\end{aligned}$$

We define our bias factor $\Cauditbiasfactor = 2$, which is the expected number of validators which will be required to issue a judgment for a work-report given a single no-show in the tranche before. Modeling by shows that this is optimal.

Later audits must be announced in a similar fashion to the first. If audit requirements lessen on the receipt of new information (a positive judgment being returned for a previous *no-show*), then any audits already announced are completed and judgments published. If audit requirements raise on the receipt of new information (an additional announcement being found without an accompanying judgment), then we announce the additional audit(s) we will undertake.

As $n$ increases with the passage of time $\mathbf{a}\sub{n}$ becomes known and defines our auditing responsibilities. We must attempt to reconstruct all work-packages and their requisite data corresponding to each work-report we must audit. This may be done through requesting erasure-coded chunks from one-third of the validators. It may also be short-cutted by asking a cooperative third party (an original guarantor) for the preimages.

Thus, for any such work-report $\wrX$ we are assured we will be able to fetch some candidate work-package encoding $F(\wrX)$ which comes either from reconstructing erasure-coded chunks verified through the erasure coding’s Merkle root, or alternatively from the preimage of the work-package hash. We decode this candidate blob into a work-package.

In addition to the work-package, we also assume we are able to fetch all manifest data associated with it through requesting and reconstructing erasure-coded chunks from one-third of validators in the same way as above.

We then attempt to reproduce the report on the core to give $e\sub{n}$, a mapping from cores to evaluations: $$\begin{aligned}
  %  \forall \tup{\cX, \wrX} \in \localSUBtranche\sub{n} \!: e\sub{n}(\wrX) \!\Leftrightarrow\! \begin{cases}
  %    \wrX = \computereport(p, \cX)\!\!\!\!\! &\when \exists p \in \workpackage: \encode{p} = F(\wrX) \\
  %    \bot &\otherwise
  %  \end{cases}
    \forall \tup{\cX, \wrX} \in \mathbf{a}\sub{n} :\ \ &\\[-10pt]
    e\sub{n}(\cX) \Leftrightarrow &\begin{cases}
      \wrX = \computereport(p, \cX)\!\!\! &\when \exists p \in \workpackage: \encode{p} = F(\wrX) \\
      \bot &\otherwise
    \end{cases}
  \end{aligned}\!\!$$

Note that a failure to decode implies an invalid work-report.

From this mapping the validator issues a set of judgments $\mathbf{j}\sub{n}$: $$\begin{aligned}
  \label{eq:judgments}
  \mathbf{j}\sub{n} &= \set{\build{
    \edsigndata{
      \activeset\subb{v}_\vkSUBed
    }{
      \Xvalidif{e\sub{n}(\cX)} \concat \blake{\wrX}
    }
  }{
    \tup{\cX, \wrX} \in \mathbf{a}\sub{n}
  }}
\end{aligned}$$

All judgments $\mathbf{j}_*$ should be published to other validators in order that they build their view of $J$ and in the case of a negative judgment arising, can form an extrinsic for $\xtdisputes$.

We consider a work-report as audited under two circumstances. Either, when it has no negative judgments and there exists some tranche in which we see a positive judgment from all validators who we believe are required to audit it; or when we see positive judgments for it from greater than two-thirds of the validator set. $$\begin{aligned}
  U(\wrX) &\Leftrightarrow \bigvee\,\abracegroup[\,]{
    &J_\bot(\wrX) = \emptyset \wedge \exists n : A\sub{n}(\wrX) \subset J_\top(\wrX) \\
    &\len{J_\top(\wrX)} > \twothirds\Cvalcount
  }
\end{aligned}$$

Our block $\block$ may be considered audited, a condition denoted $\isaudited$, when all the work-reports which were made available are considered audited. Formally: $$\begin{aligned}
  \isaudited &\Leftrightarrow \forall \wrX \in \justbecameavailable : U(\wrX)
\end{aligned}$$

For any block we must judge it to be audited ($\isaudited = \top$) before we vote for the block to be finalized in GRANDPA. See section sec:grandpa for more information here.

Furthermore, we pointedly disregard chains which include the accumulation of a report which we know at least $\onethird$ of validators judge as being invalid. Any chains including such a block are not eligible for authoring on. The *best block*, that on which we build new blocks, is defined as the chain with the most regular Safrole blocks which does *not* contain any such disregarded block. Implementation-wise, this may require reversion to an earlier head or alternative fork.

As a block author, we include a judgment extrinsic which collects judgment signatures together and reports them on-chain. In the case of a non-valid judgment (one which is not two-thirds-plus-one of judgments confirming validity) then this extrinsic will be introduced in a block in which accumulation of the non-valid work-report is about to take place. The non-valid judgment extrinsic removes it from the pending work-reports, $\reports$. Refer to section 10 for more details on this.

# Beefy Distribution

For each finalized block $\block$ which a validator imports, said validator shall make a BLS signature on the BLS- curve, as defined by , affirming the Keccak hash of the block’s most recent BEEFY MMR. This should be published and distributed freely, along with the signed material. These signatures may be aggregated in order to provide concise proofs of finality to third-party systems. The signing and aggregation mechanism is defined fully by .

Formally, let $\accoutcommitment{v}$ be the signed commitment of validator index $v$ which will be published: $$\begin{aligned}
\label{eq:accoutsignedcommitment}
  \accoutcommitment{v} &\equiv \blssigndata{\activeset'\sub{v}}{\Xbeefy \concat \text{last}(\recenthistory)_\rhSUBaccoutlogsuperpeak}\\
  \Xbeefy &= \token{\$jam\_beefy}
\end{aligned}$$

# Grandpa and the Best Chain

Nodes take part in the GRANDPA protocol as defined by .

We define the latest finalized block as $\block^\natural$. All associated terms concerning block and state are similarly superscripted. We consider the *best block*, $\block^\flat$ to be that which is drawn from the set of acceptable blocks of the following criteria:

- Has the finalized block as an ancestor.

- Contains no unfinalized blocks where we see an equivocation (two valid blocks at the same timeslot).

- Is considered audited.

Formally: $$\begin{aligned}
  \ancestors(\header^\flat) &\owns \header^\natural\\
  \isaudited^\flat&\equiv \top \\
  \not\exists \header^A, \header^B &: \bigwedge \abracegroup[\,]{
    \header^A &\ne \header^B \\
    \header^A_\SUBtimeslot &= \header^B_\SUBtimeslot \\
    \header^A &\in \ancestors(\header^\flat) \\
    \header^A &\not\in \ancestors(\header^\natural)
  }
\end{aligned}$$

Of these acceptable blocks, that which contains the most ancestor blocks whose author used a seal-key ticket, rather than a fallback key should be selected as the best head, and thus the chain on which the participant should make GRANDPA votes.

Formally, we aim to select $\block^\flat$ to maximize the value $m$ where: $$m = \sum_{\header^A \in \ancestors^\flat} \isticketed^A$$

The specific data to be voted on in GRANDPA shall be the block header of the best block, $\block^\flat$ together with its *posterior* state root, $\merklizestate{\thestate'}$. The state root has no direct relevance to the GRANDPA protocol, but is included alongside the header during voting/signing into order to ensure that systems utilizing the output of GRANDPA are able to verify the most recent chain state as possible.

This implies that the posterior state must be known at the time that GRANDPA voting occurs in order to finalize the block. However, since GRANDPA is relied on primarily for state-root verification it makes little sense to finalize a block without an associated commitment to the posterior state.

The posterior state only affects GRANDPA voting in so much as votes for the same block hash but with different associated posterior state roots are considered votes for different blocks. This would only happen in the case of a misbehaving node or an ambiguity in the present document.

# Discussion

## Technical Characteristics

In total, with our stated target of 1,023 validators and three validators per core, along with requiring a mean of ten audits per validator per timeslot, and thus 30 audits per work-report, is capable of trustlessly processing and integrating 341 work-packages per timeslot.

We assume node hardware is a modern 16 core CPU with 64GB RAM, 8TB secondary storage and 0.5Gbe networking.

Our performance models assume a rough split of CPU time as follows:

<div class="center">

|                                                                                 | *Proportion*        |     |
|:--------------------------------------------------------------------------------|:--------------------|:----|
| Audits                                                                          | $\nicefrac{10}{16}$ |     |
| Merklization                                                                    | $\nicefrac{1}{16}$  |     |
| Block execution                                                                 | $\nicefrac{2}{16}$  |     |
| GRANDPA and BEEFY | $\nicefrac{1}{16}$  |     |
| Erasure coding                                                                  | $\nicefrac{1}{16}$  |     |
| Networking & misc                                                               | $\nicefrac{1}{16}$  |     |

</div>

Estimates for network bandwidth requirements are as follows:

<div class="center">

| Throughput, MB/slot                              | *Tx*    | *Rx*    |
|:--------------------------------------------------------------------------------|:--------|:--------|
| Guaranteeing                                                                    | 106     | 48      |
| Assuring                                                                        | 144     | 13      |
| Auditing                                                                        | 0       | 133     |
| Authoring                                                                       | 53      | 87      |
| GRANDPA and BEEFY | 4       | 4       |
| **Total**                                                                       | **304** | **281** |
| **Implied bandwidth**, Mb/s                      | **387** | **357** |

</div>

Thus, a connection able to sustain 500Mb/s should leave a sufficient margin of error and headroom to serve other validators as well as some public connections, though the burstiness of block publication would imply validators are best to ensure that peak bandwidth is higher.

Under these conditions, we would expect an overall network-provided data availability capacity of 2PB, with each node dedicating at most $6$TB to availability storage.

Estimates for memory usage are as follows:

<div class="center">

|                 | GB |                                                            |
|:----------------|:----------------------------------|:-----------------------------------------------------------|
| Auditing        | 20                                | 2 $\times$ 10 PVM instances |
| Block execution | 2                                 | 1 PVM instance              |
| State cache     | 40                                |                                                            |
| Misc            | 2                                 |                                                            |
| **Total**       | **64**                            |                                                            |

</div>

As a rough guide, each parachain has an average footprint of around 2MB in the Polkadot Relay chain; a 40GB state would allow 20,000 parachains’ information to be retained in state.

What might be called the “virtual hardware” of a core is essentially a regular CPU core executing at somewhere between 25% and 50% of regular speed for the whole six-second portion and which may draw and provide 2MB/s average in general-purpose I/O and utilize up to 2GB in RAM. The I/O includes any trustless reads from the chain state, albeit in the recent past. This virtual hardware also provides unlimited reads from a semi-static preimage-lookup database.

Each work-package may occupy this hardware and execute arbitrary code on it in six-second segments to create some result of at most 48KB. This work-result is then entitled to 10ms on the same machine, this time with no “external” I/O, but instead with full and immediate access to the chain state and may alter the service(s) to which the results belong.

## Illustrating Performance

In terms of pure processing power, the machine architecture can deliver extremely high levels of homogeneous trustless computation. However, the core model of is a classic parallelized compute architecture, and for solutions to be able to utilize the architecture well they must be designed with it in mind to some extent. Accordingly, until such use-cases appear on with similar semantics to existing ones, it is very difficult to make direct comparisons to existing systems. That said, if we indulge ourselves with some assumptions then we can make some crude comparisons.

### Comparison to Polkadot

Polkadot is at present capable of validating at most 80 parachains each doing one second of native computation and 5MB of I/O in every six. This corresponds to an aggregate compute performance of around 13x native CPU and a total 24-hour distributed availability of around 67MB/s. Accumulation is beyond Polkadot’s capabilities and so not comparable.

For comparison, in our basic models, should be capable of attaining around 85x the computation load of a single native CPU core and a distributed availability of 682MB/s.

### Simple Transfers

We might also attempt to model a simple transactions-per-second amount, with each transaction requiring a signature verification and the modification of two account balances. Once again, until there are clear designs for precisely how this would work we must make some assumptions. Our most naive model would be to use the cores (refinement) simply for transaction verification and account lookups. The chain would then hold and alter the balances in its state. This is unlikely to give great performance since almost all the needed I/O would be synchronous, but it can serve as a basis.

A 12MB work-package can hold around 96k transactions at 128 bytes per transaction. However, a 48KB work-result could only encode around 6k account updates when each update is given as a pair of a 4 byte account index and 4 byte balance, resulting in a limit of 3k transactions per package, or 171k TPS in total. It is possible that the eight bytes could typically be compressed by a byte or two, increasing maximum throughput a little. Our expectations are that state updates, with highly parallelized Merklization, can be done at between 500k and 1 million reads/write per second, implying around 250k-350k TPS, depending on which turns out to be the bottleneck.

A more sophisticated model would be to use the cores for balance updates as well as transaction verification. We would have to assume that state and the transactions which operate on them can be partitioned between work-packages with some degree of efficiency, and that the 12MB of the work-package would be split between transaction data and state witness data. Our basic models predict that a 32-bit account system paginated into $2^{10}$ accounts/page and 128 bytes per transaction could, assuming only around 1% of oraclized accounts were useful, average upwards of 1.4mTPS depending on partitioning and usage characteristics. Partitioning could be done with a fixed fragmentation (essentially sharding state), a rotating partition pattern or a dynamic partitioning (which would require specialized sequencing).

Interestingly, we expect neither model to be bottlenecked in computation, meaning that transactions could be substantially more sophisticated, perhaps with more flexible cryptography or smart-contract functionality, without a significant impact on performance.

### Computation Throughput

The TPS metric does not lend itself well to measuring distributed systems’ computational performance, so we now turn to another slightly more compute-focussed benchmark: the EVM. The basic *YP* Ethereum network, now approaching a decade old, is probably the best known example of general purpose decentralized computation and makes for a reasonable yardstick. It is able to sustain a computation and I/O rate of 1.25M gas/sec, with a peak throughput of twice that. The EVM gas metric was designed to be a time-proportional metric for predicting and constraining program execution. Attempting to determine a concrete comparison to PVM throughput is non-trivial and necessarily opinionated owing to the disparity between the two platforms, including word size, endianness, stack/register architecture and memory model. However, we will attempt to determine a reasonable range of values.

EVM gas does not directly translate into native execution as it also combines state reads and writes as well as transaction input data, implying it is able to process some combination of up to 595 storage reads, 57 storage writes and 1.25M computation-gas as well as 78KB input data in each second, trading one against the other.[^13] We cannot find any analysis of the typical breakdown between storage I/O and pure computation, so to make a very conservative estimate, we assume it does all four. In reality, we would expect it to be able to do on average of each.

Our experiments[^14] show that on modern, high-end consumer hardware with a high-quality EVM implementation, we can expect somewhere between 100 and 500 gas/µs in throughput on pure-compute workloads (we specifically utilized Odd-Product, Triangle-Number and several implementations of the Fibonacci calculation). To make a conservative comparison to PVM, we propose transpilation of the EVM code into PVM code and then re-execution of it under the PolkaVM prototype.[^15]

To help estimate a reasonable lower-bound of EVM gas/µs, for workloads which are more memory and I/O intensive, we look toward real-world permissionless deployments of the EVM and see that the Moonbeam network, after correcting for the slowdown of executing within the recompiled WebAssembly platform on the somewhat conservative Polkadot hardware platform, implies a throughput of around 100 gas/µs. We therefore assert that in terms of computation, 1µs approximates to around 100-500 EVM gas on modern high-end consumer hardware.[^16]

Benchmarking and regression tests show that the prototype PVM engine has a fixed preprocessing overhead of around 5ns/byte of program code and, for arithmetic-heavy tasks at least, a marginal factor of 1.6-2% compared to EVM execution, implying an asymptotic speedup of around 50-60x. For machine code 1MB in size expected to take of the order of a second to compute, the compilation cost becomes only 0.5% of the overall time. [^17] For code not inherently suited to the 256-bit EVM ISA, we would expect substantially improved relative execution times on PVM, though more work must be done in order to gain confidence that these speed-ups are broadly applicable.

If we allow for preprocessing to take up to the same component within execution as the marginal cost (owing to, for example, an extremely large but short-running program) and for the PVM metering to imply a safety overhead of 2x to execution speeds, then we can expect a core to be able to process the equivalent of around 1,500 EVM gas/µs. Owing to the crudeness of our analysis we might reasonably predict it to be somewhere within a factor of three either way—-5,000 EVM gas/µs.

cores are each capable of 2MB/s bandwidth, which must include any state I/O and data which must be newly introduced (transactions). While writes come at comparatively little cost to the core, only requiring hashing to determine an eventual updated Merkle root, reads must be witnessed, with each one costing around 640 bytes of witness conservatively assuming a one-million entry binary Merkle trie. This would result in a maximum of a little over 3k reads/second/core, with the exact amount dependent upon how much of the bandwidth is used for newly introduced input data.

Aggregating everything across , excepting accumulation which could add further throughput, numbers can be multiplied by 341 (with the caveat that each one’s computation cannot interfere with any of the others’ except through state oraclization and accumulation). Unlike for *roll-up chain* designs such as Polkadot and Ethereum, there is no need to have persistently fragmented state. Smart-contract state may be held in a coherent format on the chain so long as any updates are made through the 8KB/core/sec work-results, which would need to contain only the hashes of the altered contracts’ state roots.

Under our modelling assumptions, we can therefore summarize:

<div class="center">

|                                                     | Eth. L1                                         | Core                                            |                                                   |
|:----------------------------------------------------|:------------------------------------------------|:------------------------------------------------|:--------------------------------------------------|
| Compute (EVM gas/µs) | $1.25^\dagger$                                  | 500-5,000                                       | 0.15-1.5M          |
| State writes (s$^{-1}$)                             | $57^\dagger$                                    | n/a                                             | n/a                                               |
| State reads (s$^{-1}$)                              | $595^\dagger$                                   | 4K${}^\ddagger$  | 1.4M${}^\ddagger$  |
| Input data (s$^{-1}$)                               | 78KB${}^\dagger$ | 2MB${}^\ddagger$ | 682MB${}^\ddagger$ |

</div>

What we can see is that ’s overall predicted performance profile implies it could be comparable to many thousands of that of the basic Ethereum L1 chain. The large factor here is essentially due to three things: spacial parallelism, as can host several hundred cores under its security apparatus; temporal parallelism, as targets continuous execution for its cores and pipelines much of the computation between blocks to ensure a constant, optimal workload; and platform optimization by using a VM and gas model which closely fits modern hardware architectures.

It must however be understood that this is a provisional and crude estimation only. It is included only for the purpose of expressing ’s performance in tangible terms. Specifically, it does not take into account:

- that these numbers are based on real performance of Ethereum and performance modelling of (though our models are based on real-world performance of the components);

- any L2 scaling which may be possible with either or Ethereum;

- the state partitioning which uses of would imply;

- the as-yet unfixed gas model for the PVM;

- that PVM/EVM comparisons are necessarily imprecise;

- (${}^\dagger$) all figures for Ethereum L1 are drawn from the same resource: on average each figure will be only $\nicefrac{1}{4}$ of this maximum.

- (${}^\ddagger$) the state reads and input data figures for are drawn from the same resource: on average each figure will be only $\nicefrac{1}{2}$ of this maximum.

We leave it as further work for an empirical analysis of performance and an analysis and comparison between and the aggregate of a hypothetical Ethereum ecosystem which included some maximal amount of L2 deployments together with full Dank-sharding and any other additional consensus elements which they would require. This, however, is out of scope for the present work.

# Conclusion

We have introduced a novel computation model which is able to make use of pre-existing crypto-economic mechanisms in order to deliver major improvements in scalability without causing persistent state-fragmentation and thus sacrificing overall cohesion. We call this overall pattern collect-refine-join-accumulate. Furthermore, we have formally defined the on-chain portion of this logic, essentially the join-accumulate portion. We call this protocol the chain.

We argue that the model of provides a novel “sweet spot”, allowing for massive amounts of computation to be done in secure, resilient consensus compared to fully-synchronous models, and yet still have strict guarantees about both timing and integration of the computation into some singleton state machine unlike persistently fragmented models.

## Further Work

While we are able to estimate theoretical computation possible given some basic assumptions and even make broad comparisons to existing systems, practical numbers are invaluable. We believe the model warrants further empirical research in order to better understand how these theoretical limits translate into real-world performance. We feel a proper cost analysis and comparison to pre-existing protocols would also be an excellent topic for further work.

We can be reasonably confident that the design of allows it to host a service under which Polkadot *parachains* could be validated, however further prototyping work is needed to understand the possible throughput which a PVM-powered metering system could support. We leave such a report as further work. Likewise, we have also intentionally omitted details of higher-level protocol elements including cryptocurrency, coretime sales, staking and regular smart-contract functionality.

A number of potential alterations to the protocol described here are being considered in order to make practical utilization of the protocol easier. These include:

- Synchronous calls between services in accumulate.

- Restrictions on the `transfer` function in order to allow for substantial parallelism over accumulation.

- The possibility of reserving substantial additional computation capacity during accumulate under certain conditions.

- Introducing Merklization into the Work Package format in order to obviate the need to have the whole package downloaded in order to evaluate its authorization.

The networking protocol is also left intentionally undefined at this stage and its description must be done in a follow-up proposal.

Validator performance is not presently tracked on-chain. We do expect this to be tracked on-chain in the final revision of the protocol, but its specific format is not yet certain and it is therefore omitted at present.

# Acknowledgements

Much of this present work is based in large part on the work of others. The Web3 Foundation research team and in particular Alistair Stewart and Jeff Burdges are responsible for ELVES, the security apparatus of Polkadot which enables the possibility of in-core computation for . The same team is responsible for Sassafras, GRANDPA and BEEFY.

Safrole is a mild simplification of Sassafras and was made under the careful review of Davide Galassi and Alistair Stewart.

The original CoreJam RFC was refined under the review of Bastian Köcher and Robert Habermeier and most of the key elements of that proposal have made their way into the present work.

The PVM is a formalization of a partially simplified *PolkaVM* software prototype, developed by Jan Bujak. Cyrill Leutwiler contributed to the empirical analysis of the PVM reported in the present work.

The *PolkaJam* team and in particular Arkadiy Paronyan, Emeric Chevalier and Dave Emett have been instrumental in the design of the lower-level aspects of the protocol, especially concerning Merklization and I/O.

Numerous contributors to the repository since publication have helped correct errors. Thank you to all.

And, of course, thanks to the awesome Lemon Jelly, a.k.a. Fred Deakin and Nick Franglen, for three of the most beautiful albums ever produced, the cover art of the first of which was inspiration for this paper’s background art.

# Polkadot Virtual Machine

## Basic Definition

We declare the general PVM function $\Psi$. We assume a single-step invocation function define $\Psi_1$ and define the full PVM recursively as a sequence of such mutations up until the single-step mutation results in a halting condition. We additionally define the function $\text{deblob}$ which extracts the instruction data, opcode bitmask and dynamic jump table from a program blob: $$\begin{aligned}
  \Psi&\colon \abracegroup{
    \tuple{\blob, \pvmreg, \gas, \sequence[13]{\pvmreg}, \ram} &\to \tuple{\set{\halt, \panic, \oog} \cup \set{\fault, \host} \times \pvmreg, \pvmreg, \signedgas, \sequence[13]{\pvmreg}, \ram}\\
    \tup{\mathbf{p}, \imath, \gascounter, \registers, {\memory}} &\mapsto \begin{cases}
      \Psi(\mathbf{p}, \imath', \gascounter', \registers', {\memory}') &\when \varepsilon = \blacktriangleright\\
      \tup{\oog, \imath, \gascounter', \registers, {\memory}} &\when \gascounter' < 0\\
      \tup{\varepsilon, 0, \gascounter', \registers', {\memory}'} &\when \varepsilon \in \set{ \panic, \halt }\\
      \tup{\varepsilon, \imath, \gascounter', \registers, {\memory}} &\otherwise
    \end{cases} \\
    \where \tup{\varepsilon, \imath', \gascounter', \registers', {\memory}'} &= \begin{cases}
      \Psi_1(\mathbf{c}, \mathbf{k}, \mathbf{j}, \imath, \gascounter, \registers, {\memory}) &\when \tup{\mathbf{c}, \mathbf{k}, \mathbf{j}} = \text{deblob}(\mathbf{p}) \\
      \tup{\panic, \imath, \gascounter, \registers, {\memory}} &\otherwise
    \end{cases}
  }\\
  \text{deblob}&\colon\abracegroup{
    \blob &\to \tuple{\blob, \bitstring, \sequence{\pvmreg}} \cup \error \\
    \mathbf{p} &\mapsto \begin{cases}
      \tup{\mathbf{c}, \mathbf{k}, \mathbf{j}} &\when \exists!\,\mathbf{c}, \mathbf{k}, \mathbf{j} : \mathbf{p} = \encode{\len{\mathbf{j}}} \concat \encode[1]{z} \concat \encode{\len{\mathbf{c}}} \concat \encode[z]{\mathbf{j}} \concat \encode{\mathbf{c}} \concat \encode{\mathbf{k}}\,,\ \len{\mathbf{k}} = \len{\mathbf{c}} \\
      \error &\otherwise
    \end{cases} \\
  }
\end{aligned}$$

The PVM exit reason $\varepsilon \in \set{\halt, \panic, \oog} \cup \set{\fault, \host} \times \pvmreg$ may be one of regular halt $\halt$, panic $\panic$ or out-of-gas $\oog$, or alternatively a host-call $\host$, in which the host-call identifier is associated, or page-fault $\fault$ in which case the address into RAM is associated.

Assuming the program blob is valid (which can be validated statically), some gas is always charged whenever execution is attempted. This is the case even if no instruction is effectively executed and machine state is unchanged (the result state is equal to the parameter).

In the case of a final halt, either through panic or success, the instruction counter returned is zero. In all other cases, the return value of the instruction counter indexes the one *which caused the exit to happen* and the machine state represents the prior state of said instruction, thus ensuring *de facto* consistency. In order to continue beyond these exit cases, some environmental factor must be adjusted; for a page-fault, RAM must be changed, for a gas-underflow, more gas must be supplied and for a host-call, the instruction-counter must be incremented and the relevant host-call state-transition performed.

## Instructions, Opcodes and Skip-distance

The program blob $\mathbf{p}$ is split into a series of octets which make up the *instruction data* $\mathbf{c}$ and the *opcode bitmask* $\mathbf{k}$ as well as the *dynamic jump table*, $\mathbf{j}$. The former two imply an instruction sequence, and by extension a *basic-block sequence*, itself a sequence of indices of the instructions which follow a *block-termination* instruction.

The latter, dynamic jump table, is a sequence of indices into the instruction data blob and is indexed into when dynamically-computed jumps are taken. It is encoded as a sequence of natural numbers (i.e. non-negative integers) each encoded with the same length in octets. This length, term $z$ above, is itself encoded prior.

The PVM counts instructions in octet terms (rather than in terms of instructions) and it is thus necessary to define which octets represent the beginning of an instruction, the opcode octet, and which do not. This is the purpose of $\mathbf{k}$, the instruction-opcode bitmask. We assert that the length of the bitmask is equal to the length of the instruction blob.

We define the Skip function $\text{skip}$ which provides the number of octets, minus one, to the next instruction’s opcode, given the index of instruction’s opcode index into $\mathbf{c}$ (and by extension $\mathbf{k}$): $$\text{skip}\colon\abracegroup{
    \N &\to \N\\
    i &\mapsto \min(24,\ j \in \N : \tup{\mathbf{k} \concat \sq{1, 1, \dots}}_{i + 1 + j} = 1)
  }$$

The Skip function appends $\mathbf{k}$ with a sequence of set bits in order to ensure a well-defined result for the final instruction $\text{skip}(\len{\mathbf{c}} - 1)$.

Given some instruction-index $i$, its opcode is readily expressed as $\mathbf{c}_i$ and the distance in octets to move forward to the next instruction is $1 + \text{skip}(i)$. However, each instruction’s “length” (defined as the number of contiguous octets starting with the opcode which are needed to fully define the instruction’s semantics) is left implicit though limited to being at most 16.

We define $\zeta$ as being equivalent to the instructions $\mathbf{c}$ except with an indefinite sequence of zeroes suffixed to ensure that no out-of-bounds access is possible. This effectively defines any otherwise-undefined arguments to the final instruction and ensures that a trap will occur if the program counter passes beyond the program code. Formally: $$\label{eq:instructions}
  \zeta\equiv \mathbf{c} \concat \sq{0, 0, \dots}$$

## Basic Blocks and Termination Instructions

Instructions of the following opcodes are considered basic-block termination instructions; other than $\token{trap}$ & $\token{fallthrough}$, they correspond to instructions which may define the instruction-counter to be something other than its prior value plus the instruction’s skip amount:

- Trap and fallthrough: $\token{trap}$ , $\token{fallthrough}$

- Jumps: $\token{jump}$ , $\token{jump\_ind}$

- Load-and-Jumps: $\token{load\_imm\_jump}$ , $\token{load\_imm\_jump\_ind}$

- Branches: $\token{branch\_eq}$ , $\token{branch\_ne}$ , $\token{branch\_ge\_u}$ , $\token{branch\_ge\_s}$ , $\token{branch\_lt\_u}$ , $\token{branch\_lt\_s}$ , $\token{branch\_eq\_imm}$ , $\token{branch\_ne\_imm}$

- Immediate branches: $\token{branch\_lt\_u\_imm}$ , $\token{branch\_lt\_s\_imm}$ , $\token{branch\_le\_u\_imm}$ , $\token{branch\_le\_s\_imm}$ , $\token{branch\_ge\_u\_imm}$ , $\token{branch\_ge\_s\_imm}$ , $\token{branch\_gt\_u\_imm}$ , $\token{branch\_gt\_s\_imm}$

We denote this set, as opcode indices rather than names, as $T$, which is a subset of all valid opcode indices $U$. We define the instruction opcode indices denoting the beginning of basic-blocks as $\varpi$: $$\varpi\equiv \left(\set{0} \cup \set{\build{n + 1 + \text{skip}(n)}{n \in \Nmax{\len{\mathbf{c}}} \wedge \mathbf{k}\sub{n} = 1 \wedge \mathbf{c}\sub{n} \in T}}\right) \cap \set{\build{n}{\mathbf{k}\sub{n} = 1 \wedge \mathbf{c}\sub{n} \in U}}$$

## Single-Step State Transition

We must now define the single-step PVM state-transition function $\Psi_1$: $$\Psi_1\colon \abracegroup{
    \tuple{\blob, \bitstring, \sequence{\pvmreg}, \pvmreg, \gas, \sequence[13]{\pvmreg}, \ram} &\to \tuple{\set{\panic, \halt, \blacktriangleright} \cup \set{\fault, \host} \times \pvmreg, \pvmreg, \signedgas, \sequence[13]{\pvmreg}, \ram}\\
    \tup{\mathbf{c}, \mathbf{k}, \mathbf{j}, \imath, \gascounter, \registers, {\memory}} &\mapsto \tup{\varepsilon^*, \imath^*, \gascounter^*, \registers^*, {\memory}^*}
  }$$

During the course of executing instructions RAM may be accessed. When an index of RAM below $2^{16}$ is required, the machine always panics immediately without further changes to its state regardless of the apparent (in)accessibility of the value. Otherwise, should the given index of RAM not be accessible then machine state remains unchanged and the exit reason is a fault with the lowest inaccessible *page address* to be read. Similarly, where RAM must be mutated and yet mutable access is not possible, then machine state is unchanged, and the exit reason is a fault with the lowest page address to be written which is inaccessible.

Formally, let $\mathbf{r}$ and $\mathbf{w}$ be the set of indices by which ${\memory}$ must be subscripted for inspection and mutation respectively in order to calculate the result of $\Psi_1$. We define the memory-access exceptional execution state $\varepsilon^\mu$ which shall, if not $\blacktriangleright$, singly effect the returned return of $\Psi_1$ as following: $$\begin{aligned}
  \using \mathbf{x} &= \set{\build{x}{x \in \mathbf{r} \wedge x \bmod 2^{32} \not\in \readable{\memory}\ \vee\ x \in \mathbf{w} \wedge x \bmod 2^{32} \not\in \writable{\memory}}} \\
  \tup{\varepsilon^*, \imath^*, \gascounter^*, \registers^*, {\memory}^*} &= \begin{cases}
    \tup{\varepsilon, \imath', \gascounter', \registers', {\memory}'} &\when \mathbf{x} = \emset \\
    \tup{\panic, \imath, \gascounter, \registers, {\memory}} &\when \min(\mathbf{x}) \bmod 2^{32} < 2^{16} \\
    \tup{\fault \times \Cpvmpagesize\floor{\min(\mathbf{x}) \bmod 2^{32} \div \Cpvmpagesize}, \imath, \gascounter, \registers, {\memory}} &\otherwise
  \end{cases}
\end{aligned}$$

We define $\varepsilon$ together with the posterior values of regular execution (denoted as prime) of each of the items of the machine state as being in accordance with the table below. When transitioning machine state for an instruction, a number of conditions typically hold true and instructions are defined essentially by their exceptions to these rules. Specifically, the machine does not halt, the instruction counter increments by one, the gas remaining is reduced by the amount corresponding to the instruction type and RAM & registers are unchanged. Formally: $$\varepsilon = \blacktriangleright,\quad \imath' = \imath + 1 + \text{skip}(\imath),\quad \gascounter' = \gascounter - \gascounter_\Delta,\quad \registers' = \registers,\quad{\memory}' = {\memory}\text{ except as indicated }$$

In the case that $\Psi_1$ takes the $\varepsilon^\mu$

We define signed/unsigned transitions for various octet widths: $$\begin{aligned}
  \label{eq:signedfunc}
  \signfunc{n \in \N}&\colon\abracegroup{
    \Nbits{8n} &\to \Z_{-2^{8n-1}\dots2^{8n-1}}\\
    a &\mapsto \begin{cases}
      a &\when a < 2^{8n-1} \\
      a -\ 2^{8n} &\otherwise
    \end{cases}
  }\\
  \unsignfunc{n \in \N}&\colon\abracegroup{
    \Z_{-2^{8n-1}\dots2^{8n-1}} &\to \Nbits{8n}\\
    a &\mapsto (2^{8n} + a) \bmod 2^{8n}
  }\\
  \label{eq:bitsfunc}
  \fnoctetstobits_{n\in\N}&\colon\abracegroup{
    \Nbits{8n} &\to \bitstring[8n]\\
    x &\mapsto \mathbf{y}: \forall i \in \Nmax{8n} : \mathbf{y}\subb{i} \Leftrightarrow \ffrac{x}{2^i}\bmod 2
  }\\
  \fnoctetstobits_{n\in\N}^{-1}&\colon\abracegroup{
    \bitstring[8n] &\to \Nbits{8n}\\
    \mathbf{x} &\mapsto y: \sum_{i \in \Nmax{8n}} \mathbf{x}\sub{i} \cdot 2^i
  }\\
  \label{eq:revbitsfunc}
  \overleftarrow{\fnoctetstobits}_{n\in\N}&\colon\abracegroup{
    \Nbits{8n} &\to \bitstring[8n]\\
    x &\mapsto \mathbf{y}: \forall i \in \Nmax{8n} : \mathbf{y}[8n - 1 - i] \Leftrightarrow \ffrac{x}{2^i}\bmod 2
  }\\
  \overleftarrow{\fnoctetstobits}_{n\in\N}^{-1}&\colon\abracegroup{
    \bitstring[8n] &\to \Nbits{8n}\\
    \mathbf{x} &\mapsto y: \sum_{i \in \Nmax{8n}} \mathbf{x}\sub{8n - 1 - i} \cdot 2^i
  }
\end{aligned}$$

Immediate arguments are encoded in little-endian format with the most-significant bit being the sign bit. They may be compactly encoded by eliding more significant octets. Elided octets are assumed to be zero if the MSB of the value is zero, and 255 otherwise. This allows for compact representation of both positive and negative encoded values. We thus define the signed extension function operating on an input of $n$ octets as $\fnsext{n}$: $$\begin{aligned}
\label{eq:signedextension}
  \fnsext{n \in \set{0, 1, 2, 3, 4, 8}}\colon\abracegroup{
    \Nbits{8n} &\to \pvmreg\\
    x &\mapsto x + \ffrac{x}{2^{8n-1}}(2^{64}-2^{8n})
  }
\end{aligned}$$

Any alterations of the program counter stemming from a static jump, call or branch must be to the start of a basic block or else a panic occurs. Hypotheticals are not considered. Formally: $$\token{branch}(b, C) \implies \tup{\varepsilon, \imath'} = \begin{cases}
    \tup{\blacktriangleright, \imath} &\when \lnot C \\
    \tup{\panic, \imath} &\otherwhen b \not\in \varpi\\
    \tup{\blacktriangleright, b} &\otherwise
  \end{cases}$$

Jumps whose next instruction is dynamically computed must use an address which may be indexed into the jump-table $\mathbf{j}$. Through a quirk of tooling[^18], we define the dynamic address required by the instructions as the jump table index incremented by one and then multiplied by our jump alignment factor $\Cpvmdynaddralign = 2$.

As with other irregular alterations to the program counter, target code index must be the start of a basic block or else a panic occurs. Formally: $$\label{eq:jumptablealignment}
  \token{djump}(a) \implies \tup{\varepsilon, \imath'} = \begin{cases}
    \tup{\halt, \imath} &\when a = 2^{32} - 2^{16}\\
    \tup{\panic, \imath} &\otherwhen a = 0 \vee a > \len{\mathbf{j}}\cdot\Cpvmdynaddralign \vee a \bmod \Cpvmdynaddralign \ne 0 \vee \mathbf{j}_{(\nicefrac{a}{\Cpvmdynaddralign}) - 1} \not\in \varpi\\
    (\blacktriangleright, \mathbf{j}_{(\nicefrac{a}{\Cpvmdynaddralign}) - 1}) &\otherwise
  \end{cases}$$

## Instruction Tables

Only instructions which are defined in the following tables and whose opcode has its corresponding bit set in the bitmask are considered valid, otherwise the instruction behaves as-if its opcode was equal to zero. Assuming $U$ denotes all valid opcode indices, formally: $$\text{opcode}\colon\abracegroup{
    \N &\to \N\\
    n &\mapsto \begin{cases}
    \mathbf{c}\sub{n} &\when \mathbf{k}\sub{n} = 1 \wedge \mathbf{c}\sub{n} \in U \\
    0 &\otherwise
    \end{cases}
  }$$

We assume the skip length $\ell$ is well-defined: $$\ell \equiv \text{skip}(\imath)$$

### Instructions without Arguments

|       |     |     |                        |
|:------|:----|:----|:-----------------------|
| 0     |     | 1   | $\varepsilon = \panic$ |
| 1-4 1 |     | 1   |                        |

### Instructions with Arguments of One Immediate

$$\begin{aligned}
  \using l_X = \min(4, \ell) \,,\quad
  \nu_X \equiv \sext{l_X}{\decode[l_X]{\zeta\subrange{\imath+1}{l_X}}}
\end{aligned}$$

|     |     |     |                                    |
|:----|:----|:----|:-----------------------------------|
| 10  |     | 1   | $\varepsilon = \host \times \nu_X$ |

### Instructions with Arguments of One Register and One Extended Width Immediate

$$\using r_A = \min(12, \zeta_{\imath+1} \bmod 16) \,,\quad
  {\registers}'_A \equiv {\registers}'_{r_A} \,,\quad
  \nu_X \equiv \decode[8]{\zeta\subrange{\imath+2}{8}}$$

|     |     |     |                           |
|:----|:----|:----|:--------------------------|
| 20  |     | 1   | ${\registers}'_A = \nu_X$ |

### Instructions with Arguments of Two Immediates

$$\begin{aligned}
    \using l_X &= \min(4, \zeta_{\imath+1} \bmod 8) \,,\quad&
    \nu_X &\equiv \sext{l_X}{\decode[l_X]{\zeta\subrange{\imath+2}{l_X}}} \\
    \using l_Y &= \min(4, \max(0, \ell - l_X - 1)) \,,\quad&
    \nu_Y &\equiv \sext{l_Y}{\decode[l_Y]{\zeta\subrange{\imath+2+l_X}{l_Y}}}
\end{aligned}$$

|        |     |     |                                                                           |
|:-------|:----|:----|:--------------------------------------------------------------------------|
| 30     |     | 1   | $\cyclic{{\memory}'}_{\nu_X} = \nu_Y \bmod 2^8$                           |
| 1-4 31 |     | 1   | $\cyclic{{\memory}'}\subrange{\nu_X}{2} = \encode[2]{\nu_Y \bmod 2^{16}}$ |
| 1-4 32 |     | 1   | $\cyclic{{\memory}'}\subrange{\nu_X}{4} = \encode[4]{\nu_Y \bmod 2^{32}}$ |
| 1-4 33 |     | 1   | $\cyclic{{\memory}'}\subrange{\nu_X}{8} = \encode[8]{\nu_Y}$              |

### Instructions with Arguments of One Offset

$$\begin{aligned}
  \using l_X = \min(4, \ell) \,,\quad
  \nu_X \equiv \imath + \signfunc{l_X}(\decode[l_X]{\zeta\subrange{\imath+1}{l_X}})
\end{aligned}$$

|     |     |     |                               |
|:----|:----|:----|:------------------------------|
| 40  |     | 1   | $\token{branch}(\nu_X, \top)$ |

### Instructions with Arguments of One Register & One Immediate

$$\begin{aligned}
    \using r_A &= \min(12, \zeta_{\imath+1} \bmod 16) \,,\quad&
    {\registers}_A &\equiv {\registers}_{r_A} \,,\quad
    {\registers}'_A \equiv {\registers}'_{r_A} \\
    \using l_X &= \min(4, \max(0, \ell - 1)) \,,\quad&
    \nu_X &\equiv \sext{l_X}{\decode[l_X]{\zeta\subrange{\imath+2}{l_X}}}
\end{aligned}$$

|        |     |     |                                                                                    |
|:-------|:----|:----|:-----------------------------------------------------------------------------------|
| 50     |     | 1   | $\token{djump}(({\registers}_A + \nu_X) \bmod 2^{32})$                             |
| 1-4 51 |     | 1   | ${\registers}'_A = \nu_X$                                                          |
| 1-4 52 |     | 1   | ${\registers}'_A = \cyclic{{\memory}}_{\nu_X}$                                     |
| 1-4 53 |     | 1   | ${\registers}'_A = \sext{1}{\cyclic{{\memory}}_{\nu_X}}$                           |
| 1-4 54 |     | 1   | ${\registers}'_A = \decode[2]{\cyclic{{\memory}}\subrange{\nu_X}{2}}$              |
| 1-4 55 |     | 1   | ${\registers}'_A = \sext{2}{\decode[2]{\cyclic{{\memory}}\subrange{\nu_X}{2}}}$    |
| 1-4 56 |     | 1   | ${\registers}'_A = \decode[4]{\cyclic{{\memory}}\subrange{\nu_X}{4}}$              |
| 1-4 57 |     | 1   | ${\registers}'_A = \sext{4}{\decode[4]{\cyclic{{\memory}}\subrange{\nu_X}{4}}}$    |
| 1-4 58 |     | 1   | ${\registers}'_A = \decode[8]{\cyclic{{\memory}}\subrange{\nu_X}{8}}$              |
| 1-4 59 |     | 1   | $\cyclic{{\memory}'}_{\nu_X} = {\registers}_A \bmod 2^8$                           |
| 1-4 60 |     | 1   | $\cyclic{{\memory}'}\subrange{\nu_X}{2} = \encode[2]{{\registers}_A \bmod 2^{16}}$ |
| 1-4 61 |     | 1   | $\cyclic{{\memory}'}\subrange{\nu_X}{4} = \encode[4]{{\registers}_A \bmod 2^{32}}$ |
| 1-4 62 |     | 1   | $\cyclic{{\memory}'}\subrange{\nu_X}{8} = \encode[8]{{\registers}_A}$              |

### Instructions with Arguments of One Register & Two Immediates

$$\begin{aligned}
    \using r_A &= \min(12, \zeta_{\imath+1} \bmod 16) \,,\quad&
    {\registers}_A &\equiv {\registers}_{r_A} \,,\quad
    {\registers}'_A \equiv {\registers}'_{r_A} \\
    \using l_X &= \min(4, \ffrac{\zeta_{\imath+1}}{16} \bmod 8) \,,\quad&
    \nu_X &= \sext{l_X}{\decode[l_X]{\zeta\subrange{\imath+2}{l_X}}} \\
    \using l_Y &= \min(4, \max(0, \ell - l_X - 1)) \,,\quad&
    \nu_Y &= \sext{l_Y}{\decode[l_Y]{\zeta\subrange{\imath+2+l_X}{l_Y}}}
\end{aligned}$$

|        |     |     |                                                                                            |
|:-------|:----|:----|:-------------------------------------------------------------------------------------------|
| 70     |     | 1   | $\cyclic{{\memory}'}_{{\registers}_A + \nu_X} = \nu_Y \bmod 2^8$                           |
| 1-4 71 |     | 1   | $\cyclic{{\memory}'}\subrange{{\registers}_A + \nu_X}{2} = \encode[2]{\nu_Y \bmod 2^{16}}$ |
| 1-4 72 |     | 1   | $\cyclic{{\memory}'}\subrange{{\registers}_A + \nu_X}{4} = \encode[4]{\nu_Y \bmod 2^{32}}$ |
| 1-4 73 |     | 1   | $\cyclic{{\memory}'}\subrange{{\registers}_A + \nu_X}{8} = \encode[8]{\nu_Y}$              |

### Instructions with Arguments of One Register, One Immediate and One Offset

$$\begin{aligned}
      \using r_A &= \min(12, \zeta_{\imath+1} \bmod 16) \,,\quad&
      {\registers}_A &\equiv {\registers}_{r_A} \,,\quad
      {\registers}'_A \equiv {\registers}'_{r_A} \\
      \using l_X &= \min(4, \ffrac{\zeta_{\imath+1}}{16} \bmod 8) \,,\quad&
      \nu_X &= \sext{l_X}{\decode[l_X]{\zeta\subrange{\imath+2}{l_X}}} \\
      \using l_Y &= \min(4, \max(0, \ell - l_X - 1)) \,,\quad&
      \nu_Y &= \imath + \signfunc{l_Y}(\decode[l_Y]{\zeta\subrange{\imath+2+l_X}{l_Y}})
  \end{aligned}$$

|        |     |     |                                                                     |
|:-------|:----|:----|:--------------------------------------------------------------------|
| 80     |     | 1   | $\token{branch}(\nu_Y, \top)\ ,\qquad {\registers}_A' = \nu_X$      |
| 1-4 81 |     | 1   | $\token{branch}(\nu_Y, {\registers}_A = \nu_X)$                     |
| 1-4 82 |     | 1   | $\token{branch}(\nu_Y, {\registers}_A \ne \nu_X)$                   |
| 1-4 83 |     | 1   | $\token{branch}(\nu_Y, {\registers}_A < \nu_X)$                     |
| 1-4 84 |     | 1   | $\token{branch}(\nu_Y, {\registers}_A \le \nu_X)$                   |
| 1-4 85 |     | 1   | $\token{branch}(\nu_Y, {\registers}_A \ge \nu_X)$                   |
| 1-4 86 |     | 1   | $\token{branch}(\nu_Y, {\registers}_A > \nu_X)$                     |
| 1-4 87 |     | 1   | $\token{branch}(\nu_Y, \signed{{\registers}_A} < \signed{\nu_X})$   |
| 1-4 88 |     | 1   | $\token{branch}(\nu_Y, \signed{{\registers}_A} \le \signed{\nu_X})$ |
| 1-4 89 |     | 1   | $\token{branch}(\nu_Y, \signed{{\registers}_A} \ge \signed{\nu_X})$ |
| 1-4 90 |     | 1   | $\token{branch}(\nu_Y, \signed{{\registers}_A} > \signed{\nu_X})$   |

### Instructions with Arguments of Two Registers

$$\begin{aligned}
  \using r_D &= \min(12, (\zeta_{\imath+1}) \bmod 16) \,,\quad&
  {\registers}_D &\equiv {\registers}_{r_D} \,,\quad
  {\registers}'_D \equiv {\registers}'_{r_D} \\
  \using r_A &= \min(12, \ffrac{\zeta_{\imath+1}}{16}) \,,\quad&
  {\registers}_A &\equiv {\registers}_{r_A} \,,\quad
  {\registers}'_A \equiv {\registers}'_{r_A} \\
\end{aligned}$$

|         |     |     |                                                                                                                                                                 |
|:--------|:----|:----|:----------------------------------------------------------------------------------------------------------------------------------------------------------------|
| 100     |     | 1   | ${\registers}'_D = {\registers}_A$                                                                                                                              |
| 1-4 101 |     | 1   | $\begin{aligned}                                                                                                                                                
                           {\registers}'_D \equiv &\min(x \in \pvmreg): \\                                                                                                              
                           &x \ge h\\                                                                                                                                                   
                           &\Nrange{x}{{\registers}_A} \not\subseteq \readable{\memory}\\                                                                                               
                           &\Nrange{x}{{\registers}_A} \subseteq \writable{\memory'}                                                                                                    
                         \end{aligned}$                                                                                                                                                 |
| 1-4 102 |     | 1   | $\displaystyle{\registers}'_D = \sum_{i = 0}^{63}\fnoctetstobits_{8}({\registers}_A)\sub{i}$                                                                    |
| 1-4 103 |     | 1   | $\displaystyle{\registers}'_D = \sum_{i = 0}^{31}\fnoctetstobits_{4}({\registers}_A \bmod 2^{32})\sub{i}$                                                       |
| 1-4 104 |     | 1   | $\displaystyle{\registers}'_D = \max(n \in \Nmax{65})\ \where \sum_{i = 0}^{i < n} \overleftarrow{\fnoctetstobits}_{8}({\registers}_A)\sub{i} = 0$              |
| 1-4 105 |     | 1   | $\displaystyle{\registers}'_D = \max(n \in \Nmax{33})\ \where \sum_{i = 0}^{i < n} \overleftarrow{\fnoctetstobits}_{4}({\registers}_A \bmod 2^{32})\sub{i} = 0$ |
| 1-4 106 |     | 1   | $\displaystyle{\registers}'_D = \max(n \in \Nmax{65})\ \where \sum_{i = 0}^{i < n} \fnoctetstobits_{8}({\registers}_A)\sub{i} = 0$                              |
| 1-4 107 |     | 1   | $\displaystyle{\registers}'_D = \max(n \in \Nmax{33})\ \where \sum_{i = 0}^{i < n} \fnoctetstobits_{4}({\registers}_A \bmod 2^{32})\sub{i} = 0$                 |
| 1-4 108 |     | 1   | ${\registers}'_D = \unsigned{\signedn{1}{{\registers}_A \bmod 2^8}}$                                                                                            |
| 1-4 109 |     | 1   | ${\registers}'_D = \unsigned{\signedn{2}{{\registers}_A \bmod 2^{16}}}$                                                                                         |
| 1-4 110 |     | 1   | ${\registers}'_D = {\registers}_A \bmod 2^{16}$                                                                                                                 |
| 1-4 111 |     | 1   | $\forall i \in \N_8 : \encode[8]{{\registers}'_D}\sub{i} = \encode[8]{{\registers}_A}_{7-i}$                                                                    |

Note, the term $h$ above refers to the beginning of the heap, the second major section of memory as defined in equation eq:memlayout as $2\Cpvminitzonesize + Z(\len{\mathbf{o}})$. If $\token{sbrk}$ instruction is invoked on a PVM instance which does not have such a memory layout, then $h = 0$.

### Instructions with Arguments of Two Registers & One Immediate

$$\begin{aligned}
  \using r_A &= \min(12, (\zeta_{\imath+1}) \bmod 16) \,,\quad&
  {\registers}_A &\equiv {\registers}_{r_A} \,,\quad
  {\registers}'_A \equiv {\registers}'_{r_A} \\
  \using r_B &= \min(12, \ffrac{\zeta_{\imath+1}}{16}) \,,\quad&
  {\registers}_B &\equiv {\registers}_{r_B} \,,\quad
  {\registers}'_B \equiv {\registers}'_{r_B} \\
  \using l_X &= \min(4, \max(0, \ell - 1)) \,,\quad&
  \nu_X &\equiv \sext{l_X}{\decode[l_X]{\zeta\subrange{\imath+2}{l_X}}}
\end{aligned}$$

|         |     |     |                                                                                                                                                                                 |
|:--------|:----|:----|:--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| 120     |     | 1   | $\cyclic{{\memory}'}_{{\registers}_B + \nu_X} = {\registers}_A \bmod 2^8$                                                                                                       |
| 1-4 121 |     | 1   | $\cyclic{{\memory}'}\subrange{{\registers}_B + \nu_X}{2} = \encode[2]{{\registers}_A \bmod 2^{16}}$                                                                             |
| 1-4 122 |     | 1   | $\cyclic{{\memory}'}\subrange{{\registers}_B + \nu_X}{4} = \encode[4]{{\registers}_A \bmod 2^{32}}$                                                                             |
| 1-4 123 |     | 1   | $\cyclic{{\memory}'}\subrange{{\registers}_B + \nu_X}{8} = \encode[8]{{\registers}_A}$                                                                                          |
| 1-4 124 |     | 1   | ${\registers}'_A = \cyclic{{\memory}}_{{\registers}_B + \nu_X}$                                                                                                                 |
| 1-4 125 |     | 1   | ${\registers}'_A = \unsigned{\signedn{1}{\cyclic{{\memory}}_{{\registers}_B + \nu_X}}}$                                                                                         |
| 1-4 126 |     | 1   | ${\registers}'_A = \decode[2]{\cyclic{{\memory}}\subrange{{\registers}_B + \nu_X}{2}}$                                                                                          |
| 1-4 127 |     | 1   | ${\registers}'_A = \unsigned{\signedn{2}{\decode[2]{\cyclic{{\memory}}\subrange{{\registers}_B + \nu_X}{2}}}}$                                                                  |
| 1-4 128 |     | 1   | ${\registers}'_A = \decode[4]{\cyclic{{\memory}}\subrange{{\registers}_B + \nu_X}{4}}$                                                                                          |
| 1-4 129 |     | 1   | ${\registers}'_A = \unsigned{\signedn{4}{\decode[4]{\cyclic{{\memory}}\subrange{{\registers}_B + \nu_X}{4}}}}$                                                                  |
| 1-4 130 |     | 1   | ${\registers}'_A = \decode[8]{\cyclic{{\memory}}\subrange{{\registers}_B + \nu_X}{8}}$                                                                                          |
| 1-4 131 |     | 1   | ${\registers}'_A = \sext{4}{({\registers}_B + \nu_X) \bmod 2^{32}}$                                                                                                             |
| 1-4 132 |     | 1   | $\forall i \in \Nmax{64} : \fnoctetstobits_{8}({\registers}'_A)\sub{i} = \fnoctetstobits_{8}({\registers}_B)\sub{i} \wedge \fnoctetstobits_{8}(\nu_X)\sub{i}$                   |
| 1-4 133 |     | 1   | $\forall i \in \Nmax{64} : \fnoctetstobits_{8}({\registers}'_A)\sub{i} = \fnoctetstobits_{8}({\registers}_B)\sub{i} \oplus \fnoctetstobits_{8}(\nu_X)\sub{i}$                   |
| 1-4 134 |     | 1   | $\forall i \in \Nmax{64} : \fnoctetstobits_{8}({\registers}'_A)\sub{i} = \fnoctetstobits_{8}({\registers}_B)\sub{i} \vee \fnoctetstobits_{8}(\nu_X)\sub{i}$                     |
| 1-4 135 |     | 1   | ${\registers}'_A = \sext{4}{({\registers}_B \cdot \nu_X) \bmod 2^{32}}$                                                                                                         |
| 1-4 136 |     | 1   | ${\registers}'_A = {\registers}_B < \nu_X$                                                                                                                                      |
| 1-4 137 |     | 1   | ${\registers}'_A = \signed{{\registers}_B} < \signed{\nu_X}$                                                                                                                    |
| 1-4 138 |     | 1   | ${\registers}'_A = \sext{4}{({\registers}_B \cdot 2^{\nu_X \bmod 32}) \bmod 2^{32}}$                                                                                            |
| 1-4 139 |     | 1   | ${\registers}'_A = \sext{4}{\floor{{\registers}_B \bmod 2^{32} \div 2^{\nu_X \bmod 32}}}$                                                                                       |
| 1-4 140 |     | 1   | ${\registers}'_A = \unsigned{\floor{\signedn{4}{{\registers}_B \bmod 2^{32} } \div 2^{\nu_X \bmod 32}}}$                                                                        |
| 1-4 141 |     | 1   | ${\registers}'_A = \sext{4}{(\nu_X + 2^{32} - {\registers}_B) \bmod 2^{32}}$                                                                                                    |
| 1-4 142 |     | 1   | ${\registers}'_A = {\registers}_B > \nu_X$                                                                                                                                      |
| 1-4 143 |     | 1   | ${\registers}'_A = \signed{{\registers}_B} > \signed{\nu_X}$                                                                                                                    |
| 1-4 144 |     | 1   | ${\registers}'_A = \sext{4}{(\nu_X \cdot 2^{{\registers}_B \bmod 32}) \bmod 2^{32}}$                                                                                            |
| 1-4 145 |     | 1   | ${\registers}'_A = \sext{4}{\floor{\nu_X \bmod 2^{32} \div 2^{{\registers}_B \bmod 32}}}$                                                                                       |
| 1-4 146 |     | 1   | ${\registers}'_A = \unsigned{\floor{\signedn{4}{\nu_X \bmod 2^{32}} \div 2^{{\registers}_B \bmod 32}}}$                                                                         |
| 1-4 147 |     | 1   | ${\registers}'_A = \begin{cases}                                                                                                                                                
                           \nu_X &\when {\registers}_B = 0\\                                                                                                                                            
                           {\registers}_A &\otherwise                                                                                                                                                   
                         \end{cases}$                                                                                                                                                                   |
| 1-4 148 |     | 1   | ${\registers}'_A = \begin{cases}                                                                                                                                                
                           \nu_X &\when {\registers}_B \ne 0\\                                                                                                                                          
                           {\registers}_A &\otherwise                                                                                                                                                   
                         \end{cases}$                                                                                                                                                                   |
| 1-4 149 |     | 1   | ${\registers}'_A = ({\registers}_B + \nu_X) \bmod 2^{64}$                                                                                                                       |
| 1-4 150 |     | 1   | ${\registers}'_A = ({\registers}_B \cdot \nu_X) \bmod 2^{64}$                                                                                                                   |
| 1-4 151 |     | 1   | ${\registers}'_A = \sext{8}{({\registers}_B \cdot 2^{\nu_X \bmod 64}) \bmod 2^{64}}$                                                                                            |
| 1-4 152 |     | 1   | ${\registers}'_A = \sext{8}{\floor{{\registers}_B \div 2^{\nu_X \bmod 64}}}$                                                                                                    |
| 1-4 153 |     | 1   | ${\registers}'_A = \unsigned{\floor{\signed{{\registers}_B} \div 2^{\nu_X \bmod 64}}}$                                                                                          |
| 1-4 154 |     | 1   | ${\registers}'_A = (\nu_X + 2^{64} - {\registers}_B) \bmod 2^{64}$                                                                                                              |
| 1-4 155 |     | 1   | ${\registers}'_A = (\nu_X \cdot 2^{{\registers}_B \bmod 64}) \bmod 2^{64}$                                                                                                      |
| 1-4 156 |     | 1   | ${\registers}'_A = \floor{\nu_X \div 2^{{\registers}_B \bmod 64}}$                                                                                                              |
| 1-4 157 |     | 1   | ${\registers}'_A = \unsigned{\floor{\signed{\nu_X} \div 2^{{\registers}_B \bmod 64}}}$                                                                                          |
| 1-4 158 |     | 1   | $\forall i \in \Nmax{64} : \fnoctetstobits_{8}({\registers}'_A)\sub{i} = \fnoctetstobits_{8}({\registers}_B)_{(i + \nu_X) \bmod 64}$                                            |
| 1-4 159 |     | 1   | $\forall i \in \Nmax{64} : \fnoctetstobits_{8}({\registers}'_A)\sub{i} = \fnoctetstobits_{8}(\nu_X)_{(i + {\registers}_B) \bmod 64}$                                            |
| 1-4 160 |     | 1   | ${\registers}'_A = \sext{4}{x} \ \where x \in \Nbits{32}, \forall i \in \Nmax{32} : \fnoctetstobits_{4}(x)\sub{i} = \fnoctetstobits_{4}({\registers}_B)_{(i + \nu_X) \bmod 32}$ |
| 1-4 161 |     | 1   | ${\registers}'_A = \sext{4}{x} \ \where x \in \Nbits{32}, \forall i \in \Nmax{32} : \fnoctetstobits_{4}(x)\sub{i} = \fnoctetstobits_{4}(\nu_X)_{(i + {\registers}_B) \bmod 32}$ |

### Instructions with Arguments of Two Registers & One Offset

$$\begin{aligned}
    \using r_A &= \min(12, (\zeta_{\imath+1}) \bmod 16) \,,\quad&
    {\registers}_A &\equiv {\registers}_{r_A} \,,\quad
    {\registers}'_A \equiv {\registers}'_{r_A} \\
    \using r_B &= \min(12, \ffrac{\zeta_{\imath+1}}{16}) \,,\quad&
    {\registers}_B &\equiv {\registers}_{r_B} \,,\quad
    {\registers}'_B \equiv {\registers}'_{r_B} \\
    \using l_X &= \min(4, \max(0, \ell - 1)) \,,\quad&
    \nu_X &\equiv \imath + \signfunc{l_X}(\decode[l_X]{\zeta\subrange{\imath+2}{l_X}})
  \end{aligned}$$

|         |     |     |                                                                              |
|:--------|:----|:----|:-----------------------------------------------------------------------------|
| 170     |     | 1   | $\token{branch}(\nu_X, {\registers}_A = {\registers}_B)$                     |
| 1-4 171 |     | 1   | $\token{branch}(\nu_X, {\registers}_A \ne {\registers}_B)$                   |
| 1-4 172 |     | 1   | $\token{branch}(\nu_X, {\registers}_A < {\registers}_B)$                     |
| 1-4 173 |     | 1   | $\token{branch}(\nu_X, \signed{{\registers}_A} < \signed{{\registers}_B})$   |
| 1-4 174 |     | 1   | $\token{branch}(\nu_X, {\registers}_A \ge {\registers}_B)$                   |
| 1-4 175 |     | 1   | $\token{branch}(\nu_X, \signed{{\registers}_A} \ge \signed{{\registers}_B})$ |

### Instruction with Arguments of Two Registers and Two Immediates

$$\begin{aligned}
    \using r_A &= \min(12, (\zeta_{\imath+1}) \bmod 16) \,,\quad&
    {\registers}_A &\equiv {\registers}_{r_A} \,,\quad
    {\registers}'_A \equiv {\registers}'_{r_A} \\
    \using r_B &= \min(12, \ffrac{\zeta_{\imath+1}}{16}) \,,\quad&
    {\registers}_B &\equiv {\registers}_{r_B} \,,\quad
    {\registers}'_B \equiv {\registers}'_{r_B} \\
    \using l_X &= \min(4, \zeta_{\imath+2} \bmod 8) \,,\quad&
    \nu_X &= \sext{l_X}{\decode[l_X]{\zeta\subrange{\imath+3}{l_X}}} \\
    \using l_Y &= \min(4, \max(0, \ell - l_X - 2)) \,,\quad&
    \nu_Y &= \sext{l_Y}{\decode[l_Y]{\zeta\subrange{\imath+3+l_X}{l_Y}}}
  \end{aligned}$$

|     |     |     |                                                                 |
|:----|:----|:----|:----------------------------------------------------------------|
| 180 |     | 1   | $\token{djump}(({\registers}_B + \nu_Y) \bmod 2^{32}) \ ,\qquad 
                       {\registers}_A' = \nu_X$                                     |

### Instructions with Arguments of Three Registers

$$\begin{aligned}
  \using r_A &= \min(12, (\zeta_{\imath+1}) \bmod 16) \,,\quad&
  {\registers}_A &\equiv {\registers}_{r_A} \,,\quad
  {\registers}'_A \equiv {\registers}'_{r_A} \\
  \using r_B &= \min(12, \ffrac{\zeta_{\imath+1}}{16}) \,,\quad&
  {\registers}_B &\equiv {\registers}_{r_B} \,,\quad
  {\registers}'_B \equiv {\registers}'_{r_B} \\
  \using r_D &= \min(12, \zeta_{\imath+2}) \,,\quad&
  {\registers}_D &\equiv {\registers}_{r_D} \,,\quad
  {\registers}'_D \equiv {\registers}'_{r_D} \\
\end{aligned}$$

<table>
<tbody>
<tr class="odd">
<td style="text-align: left;">190</td>
<td style="text-align: left;"></td>
<td style="text-align: left;">1</td>
<td style="text-align: left;"><span class="math inline">${\registers}'_D = \sext{4}{({\registers}_A + {\registers}_B) \bmod 2^{32}}$</span></td>
</tr>
<tr class="even">
<td style="text-align: left;"><span>1-4</span> 191</td>
<td style="text-align: left;"></td>
<td style="text-align: left;">1</td>
<td style="text-align: left;"><span class="math inline">${\registers}'_D = \sext{4}{({\registers}_A + 2^{32} - ({\registers}_B \bmod 2^{32})) \bmod 2^{32}}$</span></td>
</tr>
<tr class="odd">
<td style="text-align: left;"><span>1-4</span> 192</td>
<td style="text-align: left;"></td>
<td style="text-align: left;">1</td>
<td style="text-align: left;"><span class="math inline">${\registers}'_D = \sext{4}{({\registers}_A \cdot {\registers}_B) \bmod 2^{32}}$</span></td>
</tr>
<tr class="even">
<td style="text-align: left;"><span>1-4</span> 193</td>
<td style="text-align: left;"></td>
<td style="text-align: left;">1</td>
<td style="text-align: left;"><span class="math inline">${\registers}'_D = \begin{cases}
    2^{64} - 1 &amp;\when {\registers}_B \bmod 2^{32} = 0\\
    \sext{4}{\floor{({\registers}_A \bmod 2^{32}) \div ({\registers}_B \bmod 2^{32})}} &amp;\otherwise
  \end{cases}$</span></td>
</tr>
<tr class="odd">
<td style="text-align: left;"><span>1-4</span> 194</td>
<td style="text-align: left;"></td>
<td style="text-align: left;">1</td>
<td style="text-align: left;"><span class="math inline">${\registers}'_D = \begin{cases}
    2^{64} - 1 &amp;\when b = 0\\
    \unsigned{a} &amp;\when a = -2^{31} \wedge b = -1\\
    \unsigned{\text{rtz}(a \div b)} &amp;\otherwise \\[2pt]
    \multicolumn{2}{l}{\quad \where a = \signedn{4}{{\registers}_A \bmod 2^{32}}\,,\ b = \signedn{4}{{\registers}_B \bmod 2^{32}}}\\
  \end{cases}$</span></td>
</tr>
<tr class="even">
<td style="text-align: left;"><span>1-4</span> 195</td>
<td style="text-align: left;"></td>
<td style="text-align: left;">1</td>
<td style="text-align: left;"><span class="math inline">${\registers}'_D = \begin{cases}
    \sext{4}{{\registers}_A \bmod 2^{32}} &amp;\when {\registers}_B \bmod 2^{32} = 0\\
    \sext{4}{({\registers}_A \bmod 2^{32}) \bmod ({\registers}_B \bmod 2^{32})} &amp;\otherwise
  \end{cases}$</span></td>
</tr>
<tr class="odd">
<td style="text-align: left;"><span>1-4</span> 196</td>
<td style="text-align: left;"></td>
<td style="text-align: left;">1</td>
<td style="text-align: left;"><span class="math inline">${\registers}'_D = \begin{cases}
    0 &amp;\when a = -2^{31} \wedge b = -1 \\
    \unsigned{\text{smod}(a, b)} &amp;\otherwise \\[2pt]
    \multicolumn{2}{l}{\quad \where a = \signedn{4}{{\registers}_A \bmod 2^{32}}\,,\ b = \signedn{4}{{\registers}_B \bmod 2^{32}}}\\
  \end{cases}$</span></td>
</tr>
<tr class="even">
<td style="text-align: left;"><span>1-4</span> 197</td>
<td style="text-align: left;"></td>
<td style="text-align: left;">1</td>
<td style="text-align: left;"><span class="math inline">${\registers}'_D = \sext{4}{({\registers}_A \cdot 2^{{\registers}_B \bmod 32}) \bmod 2^{32}}$</span></td>
</tr>
<tr class="odd">
<td style="text-align: left;"><span>1-4</span> 198</td>
<td style="text-align: left;"></td>
<td style="text-align: left;">1</td>
<td style="text-align: left;"><span class="math inline">${\registers}'_D = \sext{4}{\floor{({\registers}_A \bmod 2^{32}) \div 2^{{\registers}_B \bmod 32}}}$</span></td>
</tr>
<tr class="even">
<td style="text-align: left;"><span>1-4</span> 199</td>
<td style="text-align: left;"></td>
<td style="text-align: left;">1</td>
<td style="text-align: left;"><span class="math inline">${\registers}'_D = \unsigned{\floor{\signedn{4}{{\registers}_A \bmod 2^{32}} \div 2^{{\registers}_B \bmod 32}}}$</span></td>
</tr>
<tr class="odd">
<td style="text-align: left;"><p><span>1-4</span></p>
<p>200</p></td>
<td style="text-align: left;"></td>
<td style="text-align: left;">1</td>
<td style="text-align: left;"><span class="math inline">${\registers}'_D = ({\registers}_A + {\registers}_B) \bmod 2^{64}$</span></td>
</tr>
<tr class="even">
<td style="text-align: left;"><span>1-4</span> 201</td>
<td style="text-align: left;"></td>
<td style="text-align: left;">1</td>
<td style="text-align: left;"><span class="math inline">${\registers}'_D = ({\registers}_A + 2^{64} - {\registers}_B) \bmod 2^{64}$</span></td>
</tr>
<tr class="odd">
<td style="text-align: left;"><span>1-4</span> 202</td>
<td style="text-align: left;"></td>
<td style="text-align: left;">1</td>
<td style="text-align: left;"><span class="math inline">${\registers}'_D = ({\registers}_A \cdot {\registers}_B) \bmod 2^{64}$</span></td>
</tr>
<tr class="even">
<td style="text-align: left;"><span>1-4</span> 203</td>
<td style="text-align: left;"></td>
<td style="text-align: left;">1</td>
<td style="text-align: left;"><span class="math inline">${\registers}'_D = \begin{cases}
    2^{64} - 1 &amp;\when {\registers}_B = 0\\
    \floor{{\registers}_A \div {\registers}_B} &amp;\otherwise
  \end{cases}$</span></td>
</tr>
<tr class="odd">
<td style="text-align: left;"><span>1-4</span> 204</td>
<td style="text-align: left;"></td>
<td style="text-align: left;">1</td>
<td style="text-align: left;"><span class="math inline">${\registers}'_D = \begin{cases}
    2^{64} - 1 &amp;\when {\registers}_B = 0\\
    {\registers}_A &amp;\when \signed{{\registers}_A} = -2^{63} \wedge \signed{{\registers}_B} = -1\\
    \unsigned{\text{rtz}(\signed{{\registers}_A} \div \signed{{\registers}_B})} &amp;\otherwise
  \end{cases}$</span></td>
</tr>
<tr class="even">
<td style="text-align: left;"><span>1-4</span> 205</td>
<td style="text-align: left;"></td>
<td style="text-align: left;">1</td>
<td style="text-align: left;"><span class="math inline">${\registers}'_D = \begin{cases}
    {\registers}_A &amp;\when {\registers}_B = 0\\
    {\registers}_A \bmod {\registers}_B &amp;\otherwise
  \end{cases}$</span></td>
</tr>
<tr class="odd">
<td style="text-align: left;"><span>1-4</span> 206</td>
<td style="text-align: left;"></td>
<td style="text-align: left;">1</td>
<td style="text-align: left;"><span class="math inline">${\registers}'_D = \begin{cases}
    0 &amp;\when \signed{{\registers}_A} = -2^{63} \wedge \signed{{\registers}_B} = -1\\
    \unsigned{\text{smod}(\signed{{\registers}_A}, \signed{{\registers}_B})} &amp;\otherwise
  \end{cases}$</span></td>
</tr>
<tr class="even">
<td style="text-align: left;"><span>1-4</span> 207</td>
<td style="text-align: left;"></td>
<td style="text-align: left;">1</td>
<td style="text-align: left;"><span class="math inline">${\registers}'_D = ({\registers}_A \cdot 2^{{\registers}_B \bmod 64}) \bmod 2^{64}$</span></td>
</tr>
<tr class="odd">
<td style="text-align: left;"><span>1-4</span> 208</td>
<td style="text-align: left;"></td>
<td style="text-align: left;">1</td>
<td style="text-align: left;"><span class="math inline">${\registers}'_D = \floor{{\registers}_A \div 2^{{\registers}_B \bmod 64}}$</span></td>
</tr>
<tr class="even">
<td style="text-align: left;"><span>1-4</span> 209</td>
<td style="text-align: left;"></td>
<td style="text-align: left;">1</td>
<td style="text-align: left;"><span class="math inline">${\registers}'_D = \unsigned{\floor{\signed{{\registers}_A} \div 2^{{\registers}_B \bmod 64}}}$</span></td>
</tr>
<tr class="odd">
<td style="text-align: left;"><p><span>1-4</span></p>
<p>210</p></td>
<td style="text-align: left;"></td>
<td style="text-align: left;">1</td>
<td style="text-align: left;"><span class="math inline">$\forall i \in \Nmax{64} : \fnoctetstobits_{8}({\registers}'_D)\sub{i} = \fnoctetstobits_{8}({\registers}_A)\sub{i} \wedge \fnoctetstobits_{8}({\registers}_B)\sub{i}$</span></td>
</tr>
<tr class="even">
<td style="text-align: left;"><span>1-4</span> 211</td>
<td style="text-align: left;"></td>
<td style="text-align: left;">1</td>
<td style="text-align: left;"><span class="math inline">$\forall i \in \Nmax{64} : \fnoctetstobits_{8}({\registers}'_D)\sub{i} = \fnoctetstobits_{8}({\registers}_A)\sub{i} \oplus \fnoctetstobits_{8}({\registers}_B)\sub{i}$</span></td>
</tr>
<tr class="odd">
<td style="text-align: left;"><span>1-4</span> 212</td>
<td style="text-align: left;"></td>
<td style="text-align: left;">1</td>
<td style="text-align: left;"><span class="math inline">$\forall i \in \Nmax{64} : \fnoctetstobits_{8}({\registers}'_D)\sub{i} = \fnoctetstobits_{8}({\registers}_A)\sub{i} \vee \fnoctetstobits_{8}({\registers}_B)\sub{i}$</span></td>
</tr>
<tr class="even">
<td style="text-align: left;"><span>1-4</span> 213</td>
<td style="text-align: left;"></td>
<td style="text-align: left;">1</td>
<td style="text-align: left;"><span class="math inline">${\registers}'_D = \unsigned{\floor{(\signed{{\registers}_A} \cdot \signed{{\registers}_B}) \div 2^{64}}}$</span></td>
</tr>
<tr class="odd">
<td style="text-align: left;"><span>1-4</span> 214</td>
<td style="text-align: left;"></td>
<td style="text-align: left;">1</td>
<td style="text-align: left;"><span class="math inline">${\registers}'_D = \floor{({\registers}_A \cdot {\registers}_B) \div 2^{64}}$</span></td>
</tr>
<tr class="even">
<td style="text-align: left;"><span>1-4</span> 215</td>
<td style="text-align: left;"></td>
<td style="text-align: left;">1</td>
<td style="text-align: left;"><span class="math inline">${\registers}'_D = \unsigned{\floor{(\signed{{\registers}_A} \cdot {\registers}_B) \div 2^{64}}}$</span></td>
</tr>
<tr class="odd">
<td style="text-align: left;"><span>1-4</span> 216</td>
<td style="text-align: left;"></td>
<td style="text-align: left;">1</td>
<td style="text-align: left;"><span class="math inline">${\registers}'_D = {\registers}_A &lt; {\registers}_B$</span></td>
</tr>
<tr class="even">
<td style="text-align: left;"><span>1-4</span> 217</td>
<td style="text-align: left;"></td>
<td style="text-align: left;">1</td>
<td style="text-align: left;"><span class="math inline">${\registers}'_D = \signed{{\registers}_A} &lt; \signed{{\registers}_B}$</span></td>
</tr>
<tr class="odd">
<td style="text-align: left;"><span>1-4</span> 218</td>
<td style="text-align: left;"></td>
<td style="text-align: left;">1</td>
<td style="text-align: left;"><span class="math inline">${\registers}'_D = \begin{cases}
    {\registers}_A &amp;\when {\registers}_B = 0\\
    {\registers}_D &amp;\otherwise
  \end{cases}$</span></td>
</tr>
<tr class="even">
<td style="text-align: left;"><span>1-4</span> 219</td>
<td style="text-align: left;"></td>
<td style="text-align: left;">1</td>
<td style="text-align: left;"><span class="math inline">${\registers}'_D = \begin{cases}
    {\registers}_A &amp;\when {\registers}_B \ne 0\\
    {\registers}_D &amp;\otherwise
  \end{cases}$</span></td>
</tr>
<tr class="odd">
<td style="text-align: left;"><span>1-4</span> 220</td>
<td style="text-align: left;"></td>
<td style="text-align: left;">1</td>
<td style="text-align: left;"><span class="math inline">$\forall i \in \Nmax{64} : \fnoctetstobits_{8}({\registers}'_D)_{(i + {\registers}_B) \bmod 64} = \fnoctetstobits_{8}({\registers}_A)\sub{i}$</span></td>
</tr>
<tr class="even">
<td style="text-align: left;"><span>1-4</span> 221</td>
<td style="text-align: left;"></td>
<td style="text-align: left;">1</td>
<td style="text-align: left;"><span class="math inline">${\registers}'_D = \sext{4}{x}\ \where x \in \Nbits{32}, \forall i \in \Nmax{32} : \fnoctetstobits_{4}(x)_{(i + {\registers}_B) \bmod 32} = \fnoctetstobits_{4}({\registers}_A)\sub{i}$</span></td>
</tr>
<tr class="odd">
<td style="text-align: left;"><span>1-4</span> 222</td>
<td style="text-align: left;"></td>
<td style="text-align: left;">1</td>
<td style="text-align: left;"><span class="math inline">$\forall i \in \Nmax{64} : \fnoctetstobits_{8}({\registers}'_D)\sub{i} = \fnoctetstobits_{8}({\registers}_A)_{(i + {\registers}_B) \bmod 64}$</span></td>
</tr>
<tr class="even">
<td style="text-align: left;"><span>1-4</span> 223</td>
<td style="text-align: left;"></td>
<td style="text-align: left;">1</td>
<td style="text-align: left;"><span class="math inline">${\registers}'_D = \sext{4}{x}\ \where x \in \Nbits{32}, \forall i \in \Nmax{32} : \fnoctetstobits_{4}(x)\sub{i} = \fnoctetstobits_{4}({\registers}_A)_{(i + {\registers}_B) \bmod 32}$</span></td>
</tr>
<tr class="odd">
<td style="text-align: left;"><span>1-4</span> 224</td>
<td style="text-align: left;"></td>
<td style="text-align: left;">1</td>
<td style="text-align: left;"><span class="math inline">$\forall i \in \Nmax{64} : \fnoctetstobits_{8}({\registers}'_D)\sub{i} = \fnoctetstobits_{8}({\registers}_A)\sub{i} \wedge \lnot \fnoctetstobits_{8}({\registers}_B)\sub{i}$</span></td>
</tr>
<tr class="even">
<td style="text-align: left;"><span>1-4</span> 225</td>
<td style="text-align: left;"></td>
<td style="text-align: left;">1</td>
<td style="text-align: left;"><span class="math inline">$\forall i \in \Nmax{64} : \fnoctetstobits_{8}({\registers}'_D)\sub{i} = \fnoctetstobits_{8}({\registers}_A)\sub{i} \vee \lnot \fnoctetstobits_{8}({\registers}_B)\sub{i}$</span></td>
</tr>
<tr class="odd">
<td style="text-align: left;"><span>1-4</span> 226</td>
<td style="text-align: left;"></td>
<td style="text-align: left;">1</td>
<td style="text-align: left;"><span class="math inline">$\forall i \in \Nmax{64} : \fnoctetstobits_{8}({\registers}'_D)\sub{i} = \lnot ( \fnoctetstobits_{8}({\registers}_A)\sub{i} \oplus \fnoctetstobits_{8}({\registers}_B)\sub{i} )$</span></td>
</tr>
<tr class="even">
<td style="text-align: left;"><span>1-4</span> 227</td>
<td style="text-align: left;"></td>
<td style="text-align: left;">1</td>
<td style="text-align: left;"><span class="math inline">${\registers}'_D = \unsigned{\max \tup{ \signed{{\registers}_A}, \signed{{\registers}_B} }}$</span></td>
</tr>
<tr class="odd">
<td style="text-align: left;"><span>1-4</span> 228</td>
<td style="text-align: left;"></td>
<td style="text-align: left;">1</td>
<td style="text-align: left;"><span class="math inline">${\registers}'_D = \max \tup{ {\registers}_A, {\registers}_B }$</span></td>
</tr>
<tr class="even">
<td style="text-align: left;"><span>1-4</span> 229</td>
<td style="text-align: left;"></td>
<td style="text-align: left;">1</td>
<td style="text-align: left;"><span class="math inline">${\registers}'_D = \unsigned{\min \tup{ \signed{{\registers}_A}, \signed{{\registers}_B} }}$</span></td>
</tr>
<tr class="odd">
<td style="text-align: left;"><span>1-4</span> 230</td>
<td style="text-align: left;"></td>
<td style="text-align: left;">1</td>
<td style="text-align: left;"><span class="math inline">${\registers}'_D = \min \tup{ {\registers}_A, {\registers}_B }$</span></td>
</tr>
</tbody>
</table>

Note that the two signed modulo operations have an idiosyncratic definition, operating as the modulo of the absolute values, but with the sign of the numerator. Formally: $$\text{smod}\colon\abracegroup{
    \tuple{\Z, \Z} &\to \Z\\
    \tup{a, b} &\mapsto \begin{cases}
      a &\when b = 0\\
      \text{sgn}(a) \cdot (\len{a} \bmod \len{b}) &\otherwise \\
    \end{cases}
  }$$

Division operations always round their result towards zero. Formally: $$\text{rtz}\colon\abracegroup{
    \Z &\to \Z\\
    x &\mapsto \begin{cases}
      \ceil{x} &\when x < 0\\
      \floor{x} &\otherwise \\
    \end{cases}
  }$$

## Host Call Definition

An extended version of the PVM invocation which is able to progress an inner *host-call* state-machine in the case of a host-call halt condition is defined as $\Psi_H$: $$\begin{aligned}
  &\Psi_H\colon \abracegroup{
    \tuple{\begin{aligned}
      &\blob, \pvmreg, \gas, \sequence[13]{\pvmreg},\\&\ram, \contextmutator{X}, X
    \end{aligned}
    }
    &\to
    \tuple{\set{\panic, \oog, \halt} \cup \set{\fault} \times \pvmreg, \pvmreg, \signedgas, \sequence[13]{\pvmreg}, \ram, X}\\
    \tup{\mathbf{c}, \imath, \gascounter, \registers, {\memory}, f, \mathbf{x}} &\mapsto \begin{cases}
      \multicolumn{2}{l}{\text{let }(\varepsilon', \imath', \gascounter', \registers', {\memory}') = \Psi(\mathbf{c}, \imath, \gascounter, \registers, {\memory}):} \\[8pt]
      \tup{\varepsilon', \imath', \gascounter', \registers', {\memory}', \mathbf{x}} &\when \varepsilon' \in \set{ \halt, \panic, \oog } \cup \set{\fault} \times \pvmreg \\[4pt]
      \begin{aligned}
        &\Psi_H(\mathbf{c}, \imath'', \gascounter'', \registers'', {\memory}'', f, \mathbf{x}'')\\[2pt]
        &\quad \where \imath'' = \imath' + 1 + \text{skip}(\imath')
      \end{aligned}
       &\when \bigwedge\abracegroup[\;]{
        &\varepsilon' = \host \times h\\[2pt]
        &\tup{\blacktriangleright, \gascounter'', \registers'', {\memory}'', \mathbf{x}''} = f(h, \gascounter', \registers', {\memory}', \mathbf{x})
      }\\[8pt]
      \tup{\varepsilon'', \imath', \gascounter'', \registers'', {\memory}'', \mathbf{x}''} &\when  \bigwedge\abracegroup[\;]{
        &\varepsilon' = \host \times h\\[2pt]
        &\tup{\varepsilon'', \gascounter'', \registers'', {\memory}'', \mathbf{x}''} = f(h, \gascounter', \registers', {\memory}', \mathbf{x})\\[2pt]
        &\varepsilon'' \in \set{\panic, \halt, \oog}
      }\\[8pt]
    \end{cases} \\
    }\!\!\!\!\!\!\!\!\\
    &\contextmutator{X} \equiv \tuple{\N, \gas, \sequence[13]{\pvmreg}, \ram, X} \to \tuple{\set{\blacktriangleright, \halt, \panic, \oog}, \gas, \sequence[13]{\pvmreg}, \ram, X}
\end{aligned}$$

As with $\Phi$, on exit the instruction counter references the instruction *which caused the exit* and the machine state is that prior to this instruction. Should the machine be invoked again using this instruction counter and code, then the same instruction which caused the exit would be executed on the proper (prior) machine state.

With $\Phi_H$, host-calls ( instructions) are in effect handled internally with the state-mutator function provided as an argument, preventing the possibility of the result being a host-call fault. Note that in the case of a successful host-call transition, we must provide the new instruction counter value $\imath''$ explicitly alongside the fresh posterior state for said instruction.

## Standard Program Initialization

The software programs which will run in each of the four instances where the PVM is utilized in the main document have a very typical setup pattern characteristic of an output of a compiler and linker. This means that RAM has sections for program-specific read-only data, read-write (heap) data and the stack. An adjunct to this, very typical of our usage patterns is an extra read-only section via which invocation-specific data may be passed (arguments). It thus makes sense to define this properly in a single initializer function. These sections are quantized into *major zones*, and one major zone is always left unallocated between sections in order to reduce accidental overrun. Sections are padded with zeroes to the nearest PVM memory page boundary.

We thus define the standard program code format $\mathbf{p}$, which includes not only the instructions and jump table (previously represented by the term $\mathbf{c}$), but also information on the state of the RAM at program start. Given program blob $\mathbf{p}$ and argument data $\mathbf{a}$, we can decode the program code $\mathbf{c}$, registers $\registers$, and RAM ${\memory}$ by invoking the standard initialization function $Y(\mathbf{p}, \mathbf{a})$: $$Y\colon\abracegroup{
  \tuple{\blob, \blob[:\Cpvminitinputsize]} &\to \tuple{\blob, \sequence[13]{\pvmreg}, \ram}? \\
  \tup{\mathbf{p}, \mathbf{a}} &\mapsto \begin{cases}
    \tup{\mathbf{c}, \registers, {\memory}} &\when \exists! \tup{\mathbf{c}, \mathbf{o}, \mathbf{w}, z, s} \text{ which satisfy equation \ref{eq:conditions}}\\
    \none &\otherwise
  \end{cases}
}$$ With conditions: $$\begin{aligned}
\label{eq:conditions}
  &\using \mathcal{E}_3(\len{\mathbf{o}}) \concat \mathcal{E}_3(\len{\mathbf{w}}) \concat \mathcal{E}_2(z) \concat \mathcal{E}_3(s) \concat \mathbf{o} \concat \mathbf{w} \concat \mathcal{E}_4(\len{\mathbf{c}}) \concat \mathbf{c} = \mathbf{p}\\
  &\Cpvminitzonesize = 2^{16}\ ,\quad\Cpvminitinputsize = 2^{24}\\
  &\using P(x \in \N) \equiv \Cpvmpagesize\ceil{ \frac{x}{\Cpvmpagesize} }\quad,\qquad Z(x \in \N) \equiv \Cpvminitzonesize\ceil{ \frac{x}{\Cpvminitzonesize} }\\
  &5\Cpvminitzonesize + Z(\len{\mathbf{o}}) + Z(\len{\mathbf{w}} + z\Cpvmpagesize) + Z(s) + \Cpvminitinputsize \leq 2^{32}
\end{aligned}$$ Thus, if the above conditions cannot be satisfied with unique values, then the result is $\none$, otherwise it is a tuple of $\mathbf{c}$ as above and ${\memory}$, $\registers$ such that: $$\label{eq:memlayout}
  \forall i \in \Nbits{32} : (({\memory}_\ramSUBvalue)\sub{i}, ({\memory}_\ramSUBaccess)_{\floor{\nicefrac{i}{\Cpvmpagesize}}}) = \bracegroup{\begin{alignedat}{5}
    &\tup{\is{\ramSUBvalue}{\mathbf{o}_{i - \Cpvminitzonesize}},\,\is{\ramSUBaccess}{R}} &&\ \when
        \Cpvminitzonesize
            &\ \leq i < \ &&
                \Cpvminitzonesize + \len{\mathbf{o}}\\
    &\tup{0, R} &&\ \when
        \Cpvminitzonesize + \len{\mathbf{o}}
            &\ \leq i < \ &&
                \Cpvminitzonesize + P(\len{\mathbf{o}}) \\
    &(\mathbf{w}_{i - (2\Cpvminitzonesize + Z(\len{\mathbf{o}}))}, W) &&\ \when
        2\Cpvminitzonesize + Z(\len{\mathbf{o}})
            &\ \leq i < \ &&
                2\Cpvminitzonesize + Z(\len{\mathbf{o}}) + \len{\mathbf{w}}\\
    &\tup{0, W} &&\ \when
        2\Cpvminitzonesize + Z(\len{\mathbf{o}}) + \len{\mathbf{w}}
            &\ \leq i < \ &&
                2\Cpvminitzonesize + Z(\len{\mathbf{o}}) + P(\len{\mathbf{w}}) + z\Cpvmpagesize\\
    &\tup{0, W} &&\ \when
        2^{32} - 2\Cpvminitzonesize - \Cpvminitinputsize - P(s)
            &\ \leq i < \ &&
                2^{32} - 2\Cpvminitzonesize - \Cpvminitinputsize\\
    &(\mathbf{a}_{i - (2^{32} - \Cpvminitzonesize - \Cpvminitinputsize)}, R) &&\ \when
        2^{32} - \Cpvminitzonesize - \Cpvminitinputsize
            &\ \leq i < \ &&
                2^{32} - \Cpvminitzonesize - \Cpvminitinputsize + \len{\mathbf{a}}\\
    &\tup{0, R} &&\ \when
        2^{32} - \Cpvminitzonesize - \Cpvminitinputsize + \len{\mathbf{a}}
            &\ \leq i < \ &&
                2^{32} - \Cpvminitzonesize - \Cpvminitinputsize + P(\len{\mathbf{a}})\\
    &\tup{0, \none} &&\otherwise&&&
  \end{alignedat}}\\$$ $$\label{eq:registers}
  \forall i \in \Nmax{13} : \registers\sub{i} = \begin{cases}
      2^{32} - 2^{16} &\when i = 0\\
      2^{32} - 2\Cpvminitzonesize - \Cpvminitinputsize &\when i = 1\\
      2^{32} - \Cpvminitzonesize - \Cpvminitinputsize &\when i = 7\\
      \len{\mathbf{a}}&\when i = 8\\
      0 &\otherwise
    \end{cases}$$

## Argument Invocation Definition

The four instances where the PVM is utilized each expect to be able to pass argument data in and receive some return data back. We thus define the common PVM program-argument invocation function $\Psi_M$: $$\Psi_M\colon \abracegroup{
    \tuple{
      \blob, \pvmreg, \gas, \blob[:\Cpvminitinputsize], \contextmutator{X}, X
    } &\to \tuple{\gas, \blob \cup \set{\panic, \oog}, X}\\
    \tup{\mathbf{p}, \imath, \gascounter, \mathbf{a}, f, \mathbf{x}} &\mapsto \begin{cases}
      \tup{0, \panic, \mathbf{x}} &\when Y(\mathbf{p}, \mathbf{a}) = \none\\
      R(\gascounter, \Psi_H(\mathbf{c}, \imath, \gascounter, \registers, {\memory}, f, \mathbf{x})) &\when Y(\mathbf{p}, \mathbf{a}) = \tup{\mathbf{c}, \registers, {\memory}}\\
      \multicolumn{2}{l}{
        \quad \where R \colon \tup{\gascounter, \tup{\begin{alignedat}{5}
          &\varepsilon,\, &&\imath',\, &&\gascounter',\\
          &\registers',\, &&{\memory}',\, &&\mathbf{x}'
        \end{alignedat}
        }} \mapsto \begin{cases}
          \tup{u, \oog, \mathbf{x}'} &\when \varepsilon = \oog \\
          \tup{u, \memory'_{\registers'_{7}\dots+\registers'_{8}}, \mathbf{x}'} &\when \varepsilon = \halt \wedge \Nrange{\registers'_{7}}{\registers'_{8}} \subseteq \readable{{\memory}'} \\
          \tup{u, \sq{}, \mathbf{x}'} &\when \varepsilon = \halt \wedge \Nrange{\registers'_{7}}{\registers'_{8}} \not\subseteq \readable{{\memory}'} \\
          \tup{u, \panic, \mathbf{x}'} &\otherwise \\
          \multicolumn{2}{l}{\quad \where u = \gascounter - \max(\gascounter', 0)}
        \end{cases}
      }\!\!\!\!\!\!\!\!
    \end{cases}
  }$$

Note that the first tuple item is the amount of gas consumed by the operation, but never greater than the amount of gas provided for the operation.

# Virtual Machine Invocations

We now define the three practical instances where we wish to invoke a PVM instance as part of the protocol. In general, we avoid introducing unbounded data as part of the basic invocation arguments in order to minimize the chance of an unexpectedly large RAM allocation, which could lead to gas inflation and unavoidable underflow. This makes for a more cumbersome interface, but one which is more predictable and easier to reason about.

## Host-Call Result Constants

$\mathtt{NONE} = 2^{64} - 1$  
The return value indicating an item does not exist.

$\mathtt{WHAT} = 2^{64} - 2$  
Name unknown.

$\mathtt{OOB} = 2^{64} - 3$  
The inner PVM memory index provided for reading/writing is not accessible.

$\mathtt{WHO} = 2^{64} - 4$  
Index unknown.

$\mathtt{FULL} = 2^{64} - 5$  
Storage full or resource already allocated.

$\mathtt{CORE} = 2^{64} - 6$  
Core index unknown.

$\mathtt{CASH} = 2^{64} - 7$  
Insufficient funds.

$\mathtt{LOW} = 2^{64} - 8$  
Gas limit too low.

$\mathtt{HUH} = 2^{64} - 9$  
The item is already solicited, cannot be forgotten or the operation is invalid due to privilege level.

$\mathtt{OK} = 0$  
The return value indicating general success.

Inner PVM invocations have their own set of result codes:

$\mathtt{HALT} = 0$  
The invocation completed and halted normally.

$\mathtt{PANIC} = 1$  
The invocation completed with a panic.

$\mathtt{FAULT} = 2$  
The invocation completed with a page fault.

$\mathtt{HOST} = 3$  
The invocation completed with a host-call fault.

$\mathtt{OOG} = 4$  
The invocation completed by running out of gas.

Note return codes for a host-call-request exit are any non-zero value less than $2^{64} - 13$.

## Is-Authorized Invocation

The Is-Authorized invocation is the first and simplest of the four, being totally stateless. It provides only host-call functions for inspecting its environment and parameters. It accepts as arguments only the core on which it should be executed, $c$. Formally, it is defined as $\Psi_I$: $$\begin{aligned}
  \label{eq:isauthinvocation}
  \Psi_I &\colon \abracegroup{
    \tuple{\workpackage, \coreindex} &\to \tuple{\blob \cup \workerror, \gas} \\
    \tup{\wpX, c} &\mapsto \begin{cases}
      \tup{\token{BAD}, 0} &\when \wpX_\wpSUBauthcode = \none \\
      \tup{\token{BIG}, 0} &\otherwhen \len{\wpX_\wpSUBauthcode} > \Cmaxauthcodesize \\
      \tup{\mathbf{r}, u} &\otherwise \\
      \multicolumn{2}{l}{\where \tup{u, \mathbf{r}, \none} = \Psi_M(\wpX_\wpSUBauthcode, 0, \Cpackageauthgas, \encode[2]{c}, F, \none)}\\
    \end{cases}\\
  } \\
  \label{eq:isauthorizedmutator}F \in \contextmutator{\emset} &\colon
    \tup{n, \gascounter, \registers, \memory} \mapsto \begin{cases}
      \Omega_G(\gascounter, \registers, \memory) &\when n = \mathtt{gas} \\
      \Omega_Y(\gascounter, \registers, \memory, \wpX, \none, \none, \none, \none, \none, \none, \none) &\when n = \mathtt{fetch} \\
      \tup{\oog, \gascounter', \registers', \memory} &\otherwhen \gascounter' < 0 \\
      \tup{\blacktriangleright, \gascounter', \registers', \memory} &\otherwise \\
      \multicolumn{2}{l}{\where \registers' = \registers \exc \registers'_7 = \mathtt{WHAT}} \\
      \multicolumn{2}{l}{\also \gascounter' = \gascounter - 10}
    \end{cases}
\end{aligned}$$

Note for the Is-Authorized host-call dispatch function $F$ in equation eq:isauthorizedmutator, we elide the host-call context since, being essentially stateless, it is always $\none$.

## Refine Invocation

We define the Refine service-account invocation function as $\Psi_R$. It has no general access to the state of the chain, with the slight exception being the ability to make a historical lookup. Beyond this it is able to create inner instances of the PVM and dictate pieces of data to export.

The historical-lookup host-call function, $\Omega_H$, is designed to give the same result regardless of the state of the chain for any time when auditing may occur (which we bound to be less than two epochs from being accumulated). The lookup anchor may be up to $\Cmaxlookupanchorage$ timeslots before the recent history and therefore adds to the potential age at the time of audit. We therefore set $\Cexpungeperiod$ to have a safety margin of eight hours: $$\Cexpungeperiod \equiv \Cmaxlookupanchorage + 4,800 = 19,200$$

The inner PVM invocation host-calls, meanwhile, depend on an integrated PVM type, which we shall denote $\pvmguest$. It holds some program code, instruction counter and RAM: $$\label{eq:pvmguest}
  \pvmguest \equiv \tuple{\isa{\pgSUBcode}{\blob}, \isa{\pgSUBram}{\ram}, \isa{\pgSUBpc}{\pvmreg}}$$

The Export host-call depends on two pieces of context; one sequence of segments (blobs of length $\Csegmentsize$) to which it may append, and the other an argument passed to the invocation function to dictate the number of segments prior which may assumed to have already been appended. The latter value ensures that an accurate segment index can be provided to the caller.

Unlike the other invocation functions, the Refine invocation function implicitly draws upon some recent service account state item $\accounts$. The specific block from which this comes is not important, as long as it is no earlier than its work-package’s lookup-anchor block. It explicitly accepts the work-package $p$ and the index of the work item to be refined, $i$ together with the core which is doing the refining $c$. Additionally, the authorizer trace $\mathbf{r}$ is provided together with all work items’ import segments $\overline{\mathbf{i}}$ and an export segment offset $\segoff$. It results in a tuple of some error $\workerror$ or the refinement output blob (signalling success), the export sequence in the case of success and the gas used in evaluation. Formally: $$\begin{aligned}
  &\Psi_R \colon \abracegroup{
    \label{eq:refinvocation}
    \tuple{\coreindex, \N, \workpackage, \blob, \sequence{\sequence{\segment}}, \N} &\to \tuple{\blob \cup \workerror, \sequence{\segment}, \gas} \\
    \tup{c, i, p, \mathbf{r}, \overline{\mathbf{i}}, \segoff} &\mapsto \begin{cases}
      \tup{\token{BAD}, \sq{}, 0} &\when w_\wiSUBserviceindex \not\in \keys{\accounts} \vee \histlookup(\accounts\subb{w_\wiSUBserviceindex}, (p_\wpSUBcontext)_\wcSUBlookupanchortime, w_\wiSUBcodehash) = \none \\
      \tup{\token{BIG}, \sq{}, 0} &\otherwhen \len{\histlookup(\accounts\subb{w_\wiSUBserviceindex}, (p_\wpSUBcontext)_\wcSUBlookupanchortime, w_\wiSUBcodehash)} > \Cmaxservicecodesize \\
      &\otherwise: \\
      &\quad\using \mathbf{a} = \encode{c, i, w_\wiSUBserviceindex, \var{w_\wiSUBpayload}, \blake{p}}\;,\ \encode{\var{\mathbf{z}}, \mathbf{c}} = \histlookup(\accounts\subb{w_\wiSUBserviceindex}, (p_\wpSUBcontext)_\wcSUBlookupanchortime, w_\wiSUBcodehash)\\
      &\quad\also \tup{u, \mathbf{o}, \tup{\mathbf{m}, \mathbf{e}}} = \Psi_M(\mathbf{c}, 0, w_\wiSUBrefgaslimit, \mathbf{a}, F, \tup{\emptyset, \sq{}})\ \colon\\
      \tup{\mathbf{o}, \sq{}, u} &\quad\when \mathbf{o} \in \set{ \oog, \panic }  \\
      \tup{\mathbf{o}, \mathbf{e}, u} &\quad\otherwise \\
      \multicolumn{2}{l}{\where w = p_\wpSUBworkitems\subb{i}}
    \end{cases} \\
  } \\
  \label{eq:refinemutator}
  &F \in \contextmutator{\tuple{\dictionary{\N}{\pvmguest}, \sequence{\segment}}} \colon
    (n, \gascounter, \registers, \memory, \tup{\mathbf{m}, \mathbf{e}}) \mapsto \begin{cases}
      \Omega_G(\gascounter, \registers, \memory, \tup{\mathbf{m}, \mathbf{e}}) &\when n = \mathtt{gas} \\
      \Omega_Y(\gascounter, \registers, \memory, p, \zerohash, \mathbf{r}, i, \overline{\mathbf{i}}, \overline{\mathbf{x}}, \none, \tup{\mathbf{m}, \mathbf{e}}) &\when n = \mathtt{fetch}\\
      \Omega_H(\gascounter, \registers, \memory, \tup{\mathbf{m}, \mathbf{e}}, w_\wiSUBserviceindex, \accounts, (p_\wpSUBcontext)_\wcSUBlookupanchortime) &\when n = \mathtt{historical\_lookup}\\
      \Omega_E(\gascounter, \registers, \memory, \tup{\mathbf{m}, \mathbf{e}}, \segoff) &\when n = \mathtt{export}\\
      \Omega_M(\gascounter, \registers, \memory, \tup{\mathbf{m}, \mathbf{e}}) &\when n = \mathtt{machine}\\
      \Omega_P(\gascounter, \registers, \memory, \tup{\mathbf{m}, \mathbf{e}}) &\when n = \mathtt{peek}\\
      \Omega_O(\gascounter, \registers, \memory, \tup{\mathbf{m}, \mathbf{e}}) &\when n = \mathtt{poke}\\
      \Omega_Z(\gascounter, \registers, \memory, \tup{\mathbf{m}, \mathbf{e}}) &\when n = \mathtt{pages}\\
      \Omega_K(\gascounter, \registers, \memory, \tup{\mathbf{m}, \mathbf{e}}) &\when n = \mathtt{invoke}\\
      \Omega_X(\gascounter, \registers, \memory, \tup{\mathbf{m}, \mathbf{e}}) &\when n = \mathtt{expunge}\\
      \tup{\oog, \gascounter', \registers', \memory} &\otherwhen \gascounter' < 0\\
      \tup{\blacktriangleright, \gascounter', \registers', \memory} &\otherwise\\
      \multicolumn{2}{l}{\where \registers' = \registers \exc \registers'_7 = \mathtt{WHAT}} \\
      \multicolumn{2}{l}{\also \gascounter' = \gascounter - 10} \\
      \multicolumn{2}{l}{\also \overline{\mathbf{x}} = \sq{\build{
        \sq{\build{
          \mathbf{x}
        }{
          \tup{\blake{\mathbf{x}}, \len{\mathbf{x}}} \orderedin \wiX_\wiSUBextrinsics
        }}
      }{
        \wiX \orderedin p_\wpSUBworkitems
      }}}
    \end{cases}
\end{aligned}$$

## Accumulate Invocation

Since this is a transition which can directly affect a substantial amount of on-chain state, our invocation context is accordingly complex. It is a tuple with elements for each of the aspects of state which can be altered through this invocation and beyond the account of the service itself includes the deferred transfer list and several dictionaries for alterations to preimage lookup state, core assignments, validator key assignments, newly created accounts and alterations to account privilege levels.

Formally, we define our result context to be $\implications$, and our invocation context to be a pair of these contexts, $\implications \times \implications$ (and thus for any value $\imX \in \implications$ there exists $\imX^2 \in \implications \times \implications$), with one dimension being the regular dimension and generally named $\imX$ and the other being the exceptional dimension and being named $\imY$. The only function which actually alters this second dimension is $\mathtt{checkpoint}$, $\Omega_C$ and so it is rarely seen. $$\begin{aligned}
\label{eq:implications}
  \implications &\equiv \tuple{
    \isa{\imSUBid}{\serviceid},
    \isa{\imSUBstate}{\partialstate},
    \isa{\imSUBnextfreeid}{\serviceid},
    \isa{\imSUBxfers}{\defxfers},
    \isa{\imSUByield}{\optional{\hash}},
    \isa{\imSUBprovisions}{\protoset{\tuple{\serviceid, \blob}}}
  }\\
  \forall \imX \in \implications :
    \imX_\imSUBself &\equiv (\imX_\imSUBstate)_\psSUBaccounts\subb{\imX_\imSUBid}
\end{aligned}$$

We define a convenience equivalence $\imX_\imSUBself$ to easily denote the accumulating service account.

We track both regular and exceptional dimensions within our context mutator, but collapse the result of the invocation to one or the other depending on whether the termination was regular or exceptional (out-of-gas or panic).

We define $\Psi_A$, the Accumulation invocation function as: $$\begin{aligned}
  \label{eq:accinvocation}
  \Psi_A& \colon\abracegroup{
    \tuple{
      \partialstate, \timeslot, \serviceid, \gas, \sequence{\accinput}
    }
    &\to \acconeout
    \\
    \tup{\aoSUBpoststate, t, s, g, \mathbf{i}} &\mapsto \begin{cases}
      \tup{
        \is{\aoSUBpoststate}{\mathbf{s}},
        \is{\aoSUBdefxfers}{\sq{}},
        \is{\aoSUByield}{\none},
        \is{\aoSUBgasused}{0},
        \is{\aoSUBprovisions}{\sq{}}
      }
        &\when \mathbf{c} = \none \vee \len{\mathbf{c}} > \Cmaxservicecodesize \\
      C(\Psi_M(\mathbf{c}, 5, g, \encode{t, s, \len{\mathbf{i}}}, F, I(\mathbf{s}, s)^2))
        &\otherwise \\
      \begin{aligned}
        &\quad\where \mathbf{c} = \aoSUBpoststate_\psSUBaccounts\subb{s}_\saSUBcode\\
        &\quad\also \mathbf{s}= \aoSUBpoststate\exc \mathbf{s}_\psSUBaccounts\subb{s}_\saSUBbalance = \aoSUBpoststate_\psSUBaccounts\subb{s}_\saSUBbalance + \sum_{r \in \mathbf{x}}r_\dxSUBamount\\
        &\quad\also \mathbf{x} = \sq{\build{i}{
          i \orderedin \mathbf{i} ,
          i \in \defxfer
        }}
      \end{aligned}\\
    \end{cases} \\
  }\\
  I&\colon\abracegroup{
    \tuple{\partialstate, \serviceid} &\to \implications\\
    \tup{\imSUBstate, \imSUBid} &\mapsto \tup{
      \imSUBid,
      \imSUBstate,
      \imSUBnextfreeid,
      \is{\imSUBxfers}{\sq{}},
      \is{\imSUByield}{\none},
      \is{\imSUBprovisions}{\sq{}}
    }\\
    &\qquad\where \imSUBnextfreeid = \text{check}((\decode[4]{\blake{\encode{\imSUBid, \entropyaccumulator', \H_\SUBtimeslot}}} \bmod (2^{32}-\Cminpublicindex-2^8)) + \Cminpublicindex) \\
  }\\
  F \in \contextmutator{\implicationspair} &\colon \tup{n, \gascounter, \registers, \memory, \imXY} \mapsto \begin{cases}
  \Omega_G(\gascounter, \registers, \memory, \imXY) &\when n = \mathtt{gas} \\
    \Omega_Y(\gascounter, \registers, \memory, \none, \entropyaccumulator', \none, \none, \none, \none, \mathbf{i}, \imXY) &\when n = \mathtt{fetch}\\
    G(\Omega_R(\gascounter, \registers, \memory, \imX_\imSUBself, \imX_\imSUBid, (\imX_\imSUBstate)_\psSUBaccounts), \imXY) &\when n = \mathtt{read} \\
    G(\Omega_W(\gascounter, \registers, \memory, \imX_\imSUBself, \imX_\imSUBid), \imXY) &\when n = \mathtt{write} \\
    G(\Omega_L(\gascounter, \registers, \memory, \imX_\imSUBself, \imX_\imSUBid, (\imX_\imSUBstate)_\psSUBaccounts), \imXY) &\when n = \mathtt{lookup} \\
    G(\Omega_I(\gascounter, \registers, \memory, \imX_\imSUBid, (\imX_\imSUBstate)_\psSUBaccounts), \imXY) &\when n = \mathtt{info} \\
    \Omega_B(\gascounter, \registers, \memory, \imXY) &\when n = \mathtt{bless}\\
    \Omega_A(\gascounter, \registers, \memory, \imXY) &\when n = \mathtt{assign}\\
    \Omega_D(\gascounter, \registers, \memory, \imXY) &\when n = \mathtt{designate}\\
    \Omega_C(\gascounter, \registers, \memory, \imXY) &\when n = \mathtt{checkpoint} \\
    \Omega_N(\gascounter, \registers, \memory, \imXY, \H_\SUBtimeslot) &\when n = \mathtt{new} \\
    \Omega_U(\gascounter, \registers, \memory, \imXY) &\when n = \mathtt{upgrade} \\
    \Omega_T(\gascounter, \registers, \memory, \imXY) &\when n = \mathtt{transfer} \\
    \Omega_J(\gascounter, \registers, \memory, \imXY, \H_\SUBtimeslot) &\when n = \mathtt{eject} \\
    \Omega_Q(\gascounter, \registers, \memory, \imXY) &\when n = \mathtt{query} \\
    \Omega_S(\gascounter, \registers, \memory, \imXY, \H_\SUBtimeslot) &\when n = \mathtt{solicit} \\
    \Omega_F(\gascounter, \registers, \memory, \imXY, \H_\SUBtimeslot) &\when n = \mathtt{forget} \\
    \Omega_\Taurus(\gascounter, \registers, \memory, \imXY) &\when n = \mathtt{yield} \\
    \Omega_\Aries(\gascounter, \registers, \memory, \imXY) &\when n = \mathtt{provide} \\
    \tup{\oog, \gascounter', \registers', \memory, \imXY} &\otherwhen \gascounter' < 0\\
    \tup{\blacktriangleright, \gascounter', \registers', \memory, \imXY} &\otherwise\\
    \multicolumn{2}{l}{\where \registers' = \registers \exc \registers'_7 = \mathtt{WHAT}} \\
    \multicolumn{2}{l}{\also \gascounter' = \gascounter - 10}
  \end{cases} \\
  G&\colon\abracegroup{
    \tuple{\tuple{\set{\blacktriangleright, \halt, \panic, \oog}, \gas, \sequence[13]{\pvmreg}, \ram, \serviceaccount}, \implicationspair} &\to \tuple{\set{\blacktriangleright, \halt, \panic, \oog}, \gas, \sequence[13]{\pvmreg}, \ram, \implicationspair} \\
    \tup{\tup{\execst, \gascounter, \registers, \memory, \mathbf{s}}, \imXY} &\mapsto \tup{\execst, \gascounter, \registers, \memory, \tup{\imX^*, \imY}} \\
    &\qquad \where \imX^* = \imX \exc \imX^*_\imSUBself = \mathbf{s}
  }\\
  C&\colon\abracegroup{
    \tuple{\gas, \blob \cup \set{\oog, \panic}, \implicationspair} &\to \acconeout \\
    \tup{\aoSUBgasused, \mathbf{o}, \imXY} &\mapsto \begin{cases}
      \tup{
        \is{\aoSUBpoststate}{\imY_\imSUBstate},
        \is{\aoSUBdefxfers}{\imY_\imSUBxfers},
        \is{\aoSUByield}{\imY_\imSUByield},
        \aoSUBgasused,
        \is{\aoSUBprovisions}{\imY_\imSUBprovisions}
      } & \when \mathbf{o} \in \set{\oog, \panic} \\
      \tup{
        \is{\aoSUBpoststate}{\imX_\imSUBstate},
        \is{\aoSUBdefxfers}{\imX_\imSUBxfers},
        \is{\aoSUByield}{\mathbf{o}},
        \aoSUBgasused,
        \is{\aoSUBprovisions}{\imXY_\imSUBprovisions}
      } & \otherwhen \mathbf{o} \in \hash \\
      \tup{
        \is{\aoSUBpoststate}{\imX_\imSUBstate},
        \is{\aoSUBdefxfers}{\imX_\imSUBxfers},
        \is{\aoSUByield}{\imX_\imSUByield},
        \aoSUBgasused,
        \is{\aoSUBprovisions}{\imX_\imSUBprovisions}
      } & \otherwise \\
    \end{cases}
  }
\end{aligned}$$

The mutator $F$ governs how this context will alter for any given parameterization, and the collapse function $C$ selects one of the two dimensions of context depending on whether the virtual machine’s halt was regular or exceptional.

The initializer function $I$ maps some partial state along with a service account index to yield a mutator context such that no alterations to the given state are implied in either exit scenario. Note that the component $a$ utilizes the random accumulator $\entropyaccumulator'$ and the block’s timeslot $\H_\SUBtimeslot$ to create a deterministic sequence of identifiers which are extremely likely to be unique.

Concretely, we create the identifier from the Blake2 hash of the identifier of the creating service, the current random accumulator $\entropyaccumulator'$ and the block’s timeslot. Thus, within a service’s accumulation it is almost certainly unique, but it is not necessarily unique across all services, nor at all times in the past. We utilize a *check* function to find the first such index in this sequence which does not already represent a service: $$\label{eq:newserviceindex}
  \text{check}(i \in \serviceid) \equiv \begin{cases}
    i &\when i \not\in \keys{\aoSUBpoststate_\psSUBaccounts} \\
    \text{check}((i - \Cminpublicindex + 1) \bmod (2^{32}-2^8-\Cminpublicindex) + \Cminpublicindex)&\otherwise
  \end{cases}$$

In the highly unlikely event that a block executes to find that a single service index has inadvertently been attached to two different services, then the block is considered invalid. Since no service can predict the identifier sequence ahead of time, they cannot intentionally disadvantage the block author.

## General Functions

We come now to defining the host functions which are utilized by the PVM invocations. Generally, these map some PVM state, including invocation context, possibly together with some additional parameters, to a new PVM state.

The general functions are all broadly of the form $\tup{\gascounter' \in \signedgas, \registers' \in \sequence[13]{\pvmreg}, \memory' \in \ram} = \Omega_\square(\gascounter \in \gas, \registers \in \sequence[13]{\pvmreg}, \memory \in \ram)$. Functions which have a result component which is equivalent to the corresponding argument may have said components elided in the description. Functions may also depend upon particular additional parameters.

Unlike the Accumulate functions in appendix 24.7, these do not mutate an accumulation context. Some, such as $\mathtt{write}$ mutate a service account and both accept and return some $\mathbf{s} \in \serviceaccount$. Others are more general functions, such as $\mathtt{fetch}$ and do not assume any context but have a parameter list suffixed with an ellipsis to denote that the context parameter may be taken and is provided transparently into its result. This allows it to be easily utilized in multiple PVM invocations.

Other than the gas-counter which is explicitly defined, elements of PVM state are each assumed to remain unchanged by the host-call unless explicitly specified. $$\begin{aligned}
  \gascounter' &\equiv \gascounter - g\\
  \tup{\execst', \registers', \memory', \mathbf{s}'} &\equiv \begin{cases}
    \tup{\oog, \registers, \memory, \mathbf{s}} &\when \gascounter < g\\
    \tup{\blacktriangleright, \registers, \memory, \mathbf{s}} \text{ except as indicated below} &\otherwise
  \end{cases}
\end{aligned}$$

= 1.5mm = 2mm

|                |                                                                                                                                                                                                                                                                                               |
|:---------------|:----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
|                |                                                                                                                                                                                                                                                                                               |
| **Identifier** |                                                                                                                                                                                                                                                                                               |
| **Gas usage**  |                                                                                                                                                                                                                                                                                               |
| 1-1(lr)2-2     |                                                                                                                                                                                                                                                                                               |
| `gas` = 0      |                                                                                                                                                                                                                                                                                               |
| $g = 10$       | $\begin{aligned}                                                                                                                                                                                                                                                                              
                      \registers'_7 &\equiv \gascounter'                                                                                                                                                                                                                                                         
                    \end{aligned}$                                                                                                                                                                                                                                                                               |
| 1-1(lr)2-2     |                                                                                                                                                                                                                                                                                               |
| `fetch` = 1    |                                                                                                                                                                                                                                                                                               |
| $g = 10$       | $\begin{aligned}                                                                                                                                                                                                                                                                              
                      \using \mathbf{v} &= \begin{cases}                                                                                                                                                                                                                                                         
                        \mathbf{c} &\when \registers_{10} = 0 \\                                                                                                                                                                                                                                                 
                        \multicolumn{2}{l}{\where \mathbf{c} = \encode{                                                                                                                                                                                                                                          
                          \begin{aligned}                                                                                                                                                                                                                                                                        
                            &\encode[8]{\Citemdeposit},                                                                                                                                                                                                                                                          
                            \encode[8]{\Cbytedeposit},                                                                                                                                                                                                                                                           
                            \encode[8]{\Cbasedeposit},                                                                                                                                                                                                                                                           
                            \encode[2]{\Ccorecount},                                                                                                                                                                                                                                                             
                            \encode[4]{\Cexpungeperiod},                                                                                                                                                                                                                                                         
                            \encode[4]{\Cepochlen},                                                                                                                                                                                                                                                              
                            \encode[8]{\Creportaccgas},\\                                                                                                                                                                                                                                                        
                            &\encode[8]{\Cpackageauthgas},                                                                                                                                                                                                                                                       
                            \encode[8]{\Cpackagerefgas},                                                                                                                                                                                                                                                         
                            \encode[8]{\Cblockaccgas},                                                                                                                                                                                                                                                           
                            \encode[2]{\Crecenthistorylen},                                                                                                                                                                                                                                                      
                            \encode[2]{\Cmaxpackageitems},                                                                                                                                                                                                                                                       
                            \encode[2]{\Cmaxreportdeps},                                                                                                                                                                                                                                                         
                            \encode[2]{\Cmaxblocktickets},\\                                                                                                                                                                                                                                                     
                            &\encode[4]{\Cmaxlookupanchorage},                                                                                                                                                                                                                                                   
                            \encode[2]{\Cticketentries},                                                                                                                                                                                                                                                         
                            \encode[2]{\Cauthpoolsize},                                                                                                                                                                                                                                                          
                            \encode[2]{\Cslotseconds},                                                                                                                                                                                                                                                           
                            \encode[2]{\Cauthqueuesize},                                                                                                                                                                                                                                                         
                            \encode[2]{\Crotationperiod},                                                                                                                                                                                                                                                        
                            \encode[2]{\Cmaxpackagexts},                                                                                                                                                                                                                                                         
                            \encode[2]{\Cassurancetimeoutperiod},\\                                                                                                                                                                                                                                              
                            &\encode[2]{\Cvalcount},                                                                                                                                                                                                                                                             
                            \encode[4]{\Cmaxauthcodesize},                                                                                                                                                                                                                                                       
                            \encode[4]{\Cmaxbundlesize},                                                                                                                                                                                                                                                         
                            \encode[4]{\Cmaxservicecodesize},                                                                                                                                                                                                                                                    
                            \encode[4]{\Cecpiecesize},                                                                                                                                                                                                                                                           
                            \encode[4]{\Cmaxpackageimports},\\                                                                                                                                                                                                                                                   
                            &\encode[4]{\Csegmentecpieces},                                                                                                                                                                                                                                                      
                            \encode[4]{\Cmaxreportvarsize},                                                                                                                                                                                                                                                      
                            \encode[4]{\Cmemosize},                                                                                                                                                                                                                                                              
                            \encode[4]{\Cmaxpackageexports},                                                                                                                                                                                                                                                     
                            \encode[4]{\Cepochtailstart}                                                                                                                                                                                                                                                         
                          \end{aligned}                                                                                                                                                                                                                                                                          
                        }}\\                                                                                                                                                                                                                                                                                     
                        n &\when n \ne \none \wedge \registers_{10} = 1 \\                                                                                                                                                                                                                                       
                        \mathbf{r} &\when \mathbf{r} \ne \none \wedge \registers_{10} = 2 \\                                                                                                                                                                                                                     
                        \overline{\mathbf{x}}[\registers_{11}]_{\registers_{12}} &\when \overline{\mathbf{x}} \ne \none \wedge \registers_{10} = 3 \wedge \registers_{11} < \len{\overline{\mathbf{x}}} \wedge \registers_{12} < \len{\overline{\mathbf{x}}[\registers_{11}]} \\                                 
                        \overline{\mathbf{x}}\subb{i}_{\registers_{11}} &\when \overline{\mathbf{x}} \ne \none \wedge i \ne \none \wedge \registers_{10} = 4 \wedge \registers_{11} < \len{\overline{\mathbf{x}}\subb{i}} \\                                                                                     
                        \overline{\mathbf{i}}[\registers_{11}]_{\registers_{12}} &\when \overline{\mathbf{i}} \ne \none \wedge \registers_{10} = 5 \wedge \registers_{11} < \len{\overline{\mathbf{i}}} \wedge \registers_{12} < \len{\overline{\mathbf{i}}[\registers_{11}]} \\                                 
                        \overline{\mathbf{i}}\subb{i}_{\registers_{11}} &\when \overline{\mathbf{i}} \ne \none \wedge i \ne \none \wedge \registers_{10} = 6 \wedge \registers_{11} < \len{\overline{\mathbf{i}}\subb{i}} \\                                                                                     
                        \encode{p} &\when p \ne \none \wedge \registers_{10} = 7 \\                                                                                                                                                                                                                              
                        p_\wpSUBauthconfig &\when p \ne \none \wedge \registers_{10} = 8 \\                                                                                                                                                                                                                      
                        p_\wpSUBauthtoken &\when p \ne \none \wedge \registers_{10} = 9 \\                                                                                                                                                                                                                       
                        \encode{p_\wpSUBcontext} &\when p \ne \none \wedge \registers_{10} = 10 \\                                                                                                                                                                                                               
                        \encode{\var{\sq{\build{S(w)}{w \orderedin p_\wpSUBworkitems}}}} &\when p \ne \none \wedge \registers_{10} = 11 \\                                                                                                                                                                       
                        S(p_\wpSUBworkitems[\registers_{11}]) &\when p \ne \none \wedge \registers_{10} = 12 \wedge \registers_{11} < \len{p_\wpSUBworkitems} \\                                                                                                                                                 
                        \multicolumn{2}{l}{\where S(w) \equiv \encode{\encode[4]{w_\wiSUBserviceindex}, w_\wiSUBcodehash, \encode[8]{w_\wiSUBrefgaslimit, w_\wiSUBaccgaslimit}, \encode[2]{w_\wiSUBexportcount, \len{w_\wiSUBimportsegments}, \len{w_\wiSUBextrinsics}}, \encode[4]{\len{w_\wiSUBpayload}}}} \\  
                        p_\wpSUBworkitems[\registers_{11}]_\wiSUBpayload &\when p \ne \none \wedge \registers_{10} = 13 \wedge \registers_{11} < \len{p_\wpSUBworkitems} \\                                                                                                                                      
                        \encode{\var{\mathbf{i}}} &\when \mathbf{i} \ne \none \wedge \registers_{10} = 14 \\                                                                                                                                                                                                     
                        \encode{\mathbf{i}[\registers_{11}]} &\when \mathbf{i} \ne \none \wedge \registers_{10} = 15 \wedge \registers_{11} < \len{\mathbf{i}} \\                                                                                                                                                
                        \none &\otherwise                                                                                                                                                                                                                                                                        
                      \end{cases} \\                                                                                                                                                                                                                                                                             
                      \using o &= \registers_7 \\                                                                                                                                                                                                                                                                
                      \using f &= \min(\registers_8, \len{\mathbf{v}}) \\                                                                                                                                                                                                                                        
                      \using l &= \min(\registers_9, \len{\mathbf{v}} - f) \\                                                                                                                                                                                                                                    
                      \tup{\execst', \registers'_7, \memory'\subrange{o}{l}} &\equiv \begin{cases}                                                                                                                                                                                                               
                        \tup{\panic, \registers_7, \memory\subrange{o}{l}} &\when \Nrange{o}{l} \not\subseteq \writable{\memory} \\                                                                                                                                                                              
                        \tup{\blacktriangleright, \mathtt{NONE}, \memory\subrange{o}{l}} &\otherwhen \mathbf{v} = \none \\                                                                                                                                                                                       
                        \tup{\blacktriangleright, \len{\mathbf{v}}, \mathbf{v}\subrange{f}{l}} &\otherwise \\                                                                                                                                                                                                    
                      \end{cases}                                                                                                                                                                                                                                                                                
                    \end{aligned}$                                                                                                                                                                                                                                                                               |
| 1-1(lr)2-2     |                                                                                                                                                                                                                                                                                               |
| `lookup` = 2   |                                                                                                                                                                                                                                                                                               |
| $g = 10$       | $\begin{aligned}                                                                                                                                                                                                                                                                              
                      \using \mathbf{a} &= \begin{cases}                                                                                                                                                                                                                                                         
                        \mathbf{s} &\when \registers_7 \in \set{ s, 2^{64} - 1 } \\                                                                                                                                                                                                                              
                        \mathbf{d}[\registers_7] &\otherwhen \registers_7 \in \keys{\mathbf{d}} \\                                                                                                                                                                                                               
                        \none &\otherwise                                                                                                                                                                                                                                                                        
                      \end{cases} \\                                                                                                                                                                                                                                                                             
                      \using \sq{h, o} &= \registers\subrange{8}{2} \\                                                                                                                                                                                                                                           
                      \using \mathbf{v} &= \begin{cases}                                                                                                                                                                                                                                                         
                        \error &\when \Nrange{h}{32} \not\subseteq \readable{\memory} \\                                                                                                                                                                                                                         
                        \none &\otherwhen \mathbf{a} = \none \vee \memory\subrange{h}{32} \not\in \keys{\mathbf{a}_\saSUBpreimages} \\                                                                                                                                                                           
                        \mathbf{a}_\saSUBpreimages[\memory\subrange{h}{32}] &\otherwise \\                                                                                                                                                                                                                       
                      \end{cases} \\                                                                                                                                                                                                                                                                             
                      \using f &= \min(\registers_{10}, \len{\mathbf{v}}) \\                                                                                                                                                                                                                                     
                      \using l &= \min(\registers_{11}, \len{\mathbf{v}} - f) \\                                                                                                                                                                                                                                 
                      \tup{\execst', \registers'_7, \memory'\subrange{o}{l}} &\equiv \begin{cases}                                                                                                                                                                                                               
                        \tup{\panic, \registers_7, \memory\subrange{o}{l}} &\when \mathbf{v} = \error \vee \Nrange{o}{l} \not\subseteq \writable{\memory}\\                                                                                                                                                      
                        \tup{\blacktriangleright, \mathtt{NONE}, \memory\subrange{o}{l}} &\otherwhen \mathbf{v} = \none \\                                                                                                                                                                                       
                        \tup{\blacktriangleright, \len{\mathbf{v}}, \mathbf{v}\subrange{f}{l}} &\otherwise \\                                                                                                                                                                                                    
                      \end{cases}                                                                                                                                                                                                                                                                                
                    \end{aligned}$                                                                                                                                                                                                                                                                               |
| 1-1(lr)2-2     |                                                                                                                                                                                                                                                                                               |
| `read` = 3     |                                                                                                                                                                                                                                                                                               |
| $g = 10$       | $\begin{aligned}                                                                                                                                                                                                                                                                              
                      \using s^* &= \begin{cases}                                                                                                                                                                                                                                                                
                        s &\when \registers_7 = 2^{64} - 1 \\                                                                                                                                                                                                                                                    
                        \registers_7 &\otherwise                                                                                                                                                                                                                                                                 
                      \end{cases} \\                                                                                                                                                                                                                                                                             
                      \using \mathbf{a} &= \begin{cases}                                                                                                                                                                                                                                                         
                        \mathbf{s} &\when s^* = s \\                                                                                                                                                                                                                                                             
                        \mathbf{d}[s^*] &\otherwhen s^* \in \keys{\mathbf{d}} \\                                                                                                                                                                                                                                 
                        \none &\otherwise                                                                                                                                                                                                                                                                        
                      \end{cases} \\                                                                                                                                                                                                                                                                             
                      \using \sq{k_O, k_Z, o} &= \registers\subrange{8}{3} \\                                                                                                                                                                                                                                    
                      \using \mathbf{v} &= \begin{cases}                                                                                                                                                                                                                                                         
                        \error &\when \Nrange{k_O}{k_Z} \not\subseteq \readable{\memory} \\                                                                                                                                                                                                                      
                        \mathbf{a}_\saSUBstorage\subb{\mathbf{k}} &\otherwhen \mathbf{a} \ne \none \wedge \mathbf{k} \in \keys{\mathbf{a}_\saSUBstorage}\,,\ \where \mathbf{k} = \memory\subrange{k_O}{k_Z} \\                                                                                                   
                        \none &\otherwise                                                                                                                                                                                                                                                                        
                      \end{cases} \\                                                                                                                                                                                                                                                                             
                      \using f &= \min(\registers_{11}, \len{\mathbf{v}}) \\                                                                                                                                                                                                                                     
                      \using l &= \min(\registers_{12}, \len{\mathbf{v}} - f) \\                                                                                                                                                                                                                                 
                      \tup{\execst', \registers'_7, \memory'\subrange{o}{l}} &\equiv \begin{cases}                                                                                                                                                                                                               
                        \tup{\panic, \registers_7, \memory\subrange{o}{l}} &\when \mathbf{v} = \error \vee \Nrange{o}{l} \not\subseteq \writable{\memory}\\                                                                                                                                                      
                        \tup{\blacktriangleright, \mathtt{NONE}, \memory\subrange{o}{l}} &\otherwhen \mathbf{v} = \none \\                                                                                                                                                                                       
                        \tup{\blacktriangleright, \len{\mathbf{v}}, \mathbf{v}\subrange{f}{l}} &\otherwise \\                                                                                                                                                                                                    
                      \end{cases}                                                                                                                                                                                                                                                                                
                    \end{aligned}$                                                                                                                                                                                                                                                                               |
| 1-1(lr)2-2     |                                                                                                                                                                                                                                                                                               |
| `write` = 4    |                                                                                                                                                                                                                                                                                               |
| $g = 10$       | $\begin{aligned}                                                                                                                                                                                                                                                                              
                      \using \sq{k_O, k_Z, v_O, v_Z} &= \registers\subrange{7}{4} \\                                                                                                                                                                                                                             
                      \using \mathbf{k} &= \begin{cases}                                                                                                                                                                                                                                                         
                        \memory\subrange{k_O}{k_Z} &\when \Nrange{k_O}{k_Z} \subseteq \readable{\memory} \\                                                                                                                                                                                                      
                        \error &\otherwise                                                                                                                                                                                                                                                                       
                      \end{cases} \\                                                                                                                                                                                                                                                                             
                      \using \mathbf{a} &= \begin{cases}                                                                                                                                                                                                                                                         
                        \mathbf{s}\,,\ \exc \keys{\mathbf{a}_\saSUBstorage} = \keys{\mathbf{a}_\saSUBstorage} \setminus \set{k} & \when v_Z = 0 \\                                                                                                                                                               
                        \mathbf{s}\,,\ \exc \mathbf{a}_\saSUBstorage\subb{\mathbf{k}} = \memory\subrange{v_O}{v_Z} &\otherwhen \Nrange{v_O}{v_Z} \subseteq \readable{\memory} \\                                                                                                                                 
                        \error &\otherwise                                                                                                                                                                                                                                                                       
                      \end{cases} \\                                                                                                                                                                                                                                                                             
                      \using l &= \begin{cases}                                                                                                                                                                                                                                                                  
                        \len{\mathbf{s}_\saSUBstorage\subb{k}} &\when \mathbf{k} \in \keys{\mathbf{s}_\saSUBstorage} \\                                                                                                                                                                                          
                        \mathtt{NONE} &\otherwise                                                                                                                                                                                                                                                                
                      \end{cases} \\                                                                                                                                                                                                                                                                             
                      \tup{\execst', \registers'_7, \mathbf{s}'} &\equiv \begin{cases}                                                                                                                                                                                                                           
                        \tup{\panic, \registers_7, \mathbf{s}} &\when \mathbf{k} = \error \vee \mathbf{a} = \error\\                                                                                                                                                                                             
                        \tup{\blacktriangleright, \mathtt{FULL}, \mathbf{s}} &\otherwhen \mathbf{a}_\saSUBminbalance > \mathbf{a}_\saSUBbalance \\                                                                                                                                                               
                        \tup{\blacktriangleright, l, \mathbf{a}} &\otherwise\\                                                                                                                                                                                                                                   
                      \end{cases}                                                                                                                                                                                                                                                                                
                    \end{aligned}$                                                                                                                                                                                                                                                                               |
| 1-1(lr)2-2     |                                                                                                                                                                                                                                                                                               |
| `info` = 5     |                                                                                                                                                                                                                                                                                               |
| $g = 10$       | $\begin{aligned}                                                                                                                                                                                                                                                                              
                      \using \mathbf{a} &= \begin{cases}                                                                                                                                                                                                                                                         
                        \mathbf{d}\subb{s} &\when \registers_7 = 2^{64} - 1 \\                                                                                                                                                                                                                                   
                        \mathbf{d}\subb{\registers_7} &\otherwise                                                                                                                                                                                                                                                
                      \end{cases} \\                                                                                                                                                                                                                                                                             
                      \using o &= \registers_8 \\                                                                                                                                                                                                                                                                
                      \using \mathbf{v} &= \begin{cases}                                                                                                                                                                                                                                                         
                        \encode{                                                                                                                                                                                                                                                                                 
                          \mathbf{a}_\saSUBcodehash,                                                                                                                                                                                                                                                             
                          \encode[8]{\mathbf{a}_\saSUBbalance, \mathbf{a}_\saSUBminbalance, \mathbf{a}_\saSUBminaccgas, \mathbf{a}_\saSUBminmemogas, \mathbf{a}_\saSUBoctets},                                                                                                                                   
                          \encode[4]{\mathbf{a}_\saSUBitems},                                                                                                                                                                                                                                                    
                          \encode[8]{\mathbf{a}_\saSUBgratis},                                                                                                                                                                                                                                                   
                          \encode[4]{\mathbf{a}_\saSUBcreated, \mathbf{a}_\saSUBlastacc, \mathbf{a}_\saSUBparent}                                                                                                                                                                                                
                        } &\when \mathbf{a} \ne \none \\                                                                                                                                                                                                                                                         
                        \none &\otherwise                                                                                                                                                                                                                                                                        
                      \end{cases} \\                                                                                                                                                                                                                                                                             
                      \using f &= \min(\registers_{9}, \len{\mathbf{v}}) \\                                                                                                                                                                                                                                      
                      \using l &= \min(\registers_{10}, \len{\mathbf{v}} - f) \\                                                                                                                                                                                                                                 
                      \tup{\execst', \registers'_7, \memory'\subrange{o}{l}} &\equiv \begin{cases}                                                                                                                                                                                                               
                        \tup{\panic, \registers_7, \memory\subrange{o}{l}} &\when \mathbf{v} = \error \vee \Nrange{o}{l} \not\subseteq \writable{\memory}\\                                                                                                                                                      
                        \tup{\blacktriangleright, \mathtt{NONE}, \memory\subrange{o}{l}} &\otherwhen \mathbf{v} = \none \\                                                                                                                                                                                       
                        \tup{\blacktriangleright, \len{\mathbf{v}}, \mathbf{v}\subrange{f}{l}} &\otherwise \\                                                                                                                                                                                                    
                      \end{cases}                                                                                                                                                                                                                                                                                
                    \end{aligned}$                                                                                                                                                                                                                                                                               |

## Refine Functions

These assume some refine context pair $\tup{\mathbf{m}, \mathbf{e}} \in \tuple{\dictionary{\N}{\pvmguest}, \sequence{\segment}}$, which are both initially empty. Other than the gas-counter which is explicitly defined, elements of PVM state are each assumed to remain unchanged by the host-call unless explicitly specified. $$\begin{aligned}
  \gascounter' &\equiv \gascounter - g\\
  \tup{\execst', \registers', \memory'} &\equiv \begin{cases}
    \tup{\oog, \registers, \memory} &\when \gascounter < g\\
    \tup{\blacktriangleright, \registers, \memory} \text{ except as indicated below} &\otherwise
  \end{cases}
\end{aligned}$$

|                         |                                                                                                                                                                            |
|:------------------------|:---------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
|                         |                                                                                                                                                                            |
| **Identifier**          |                                                                                                                                                                            |
| **Gas usage**           |                                                                                                                                                                            |
| 1-1(lr)2-2              |                                                                                                                                                                            |
| `historical_lookup` = 6 |                                                                                                                                                                            |
| $g = 10$                | $\begin{aligned}                                                                                                                                                           
                               \using \mathbf{a} &= \begin{cases}                                                                                                                                      
                                 \mathbf{d}\subb{s} &\when \registers_7 = 2^{64} - 1 \wedge s \in \keys{\mathbf{d}} \\                                                                                 
                                 \mathbf{d}[\registers_7] &\when \registers_7 \in \keys{\mathbf{d}} \\                                                                                                 
                                 \none &\otherwise                                                                                                                                                     
                               \end{cases} \\                                                                                                                                                          
                               \using \sq{h, o} &= \registers\subrange{8}{2} \\                                                                                                                        
                               \using \mathbf{v} &= \begin{cases}                                                                                                                                      
                                 \error &\when \Nrange{h}{32} \not\subseteq \readable{\memory} \\                                                                                                      
                                 \none &\otherwhen \mathbf{a} = \none \\                                                                                                                               
                                 \histlookup(\mathbf{a}, t, \memory\subrange{h}{32}) &\otherwise \\                                                                                                    
                               \end{cases} \\                                                                                                                                                          
                               \using f &= \min(\registers_{10}, \len{\mathbf{v}}) \\                                                                                                                  
                               \using l &= \min(\registers_{11}, \len{\mathbf{v}} - f) \\                                                                                                              
                               \tup{\execst', \registers'_7, \memory'\subrange{o}{l}} &\equiv \begin{cases}                                                                                            
                                 \tup{\panic, \registers_7, \memory\subrange{o}{l}} &\when \mathbf{v} = \error \vee \Nrange{o}{l} \not\subseteq \writable{\memory}\\                                   
                                 \tup{\blacktriangleright, \mathtt{NONE}, \memory\subrange{o}{l}} &\otherwhen \mathbf{v} = \none \\                                                                    
                                 \tup{\blacktriangleright, \len{\mathbf{v}}, \mathbf{v}\subrange{f}{l}} &\otherwise \\                                                                                 
                               \end{cases}                                                                                                                                                             
                             \end{aligned}$                                                                                                                                                            |
| 1-1(lr)2-2              |                                                                                                                                                                            |
| `export` = 7            |                                                                                                                                                                            |
| $g = 10$                | $\begin{aligned}                                                                                                                                                           
                               \using p &= \registers_7 \\                                                                                                                                             
                               \using z &= \min(\registers_8, \Csegmentsize) \\                                                                                                                        
                               \using \mathbf{x} &= \begin{cases}                                                                                                                                      
                                 \zeropad{\Csegmentsize}{{\memory}\subrange{p}{z}} &\when \Nrange{p}{z} \subseteq \readable[\memory]\\                                                                 
                                 \error &\otherwise                                                                                                                                                    
                               \end{cases}\\                                                                                                                                                           
                               \tup{\execst', \registers'_7, \mathbf{e}'} &\equiv \begin{cases}                                                                                                        
                                 \tup{\panic, \registers_7, \mathbf{e}} &\when \mathbf{x} = \error \\                                                                                                  
                                 \tup{\blacktriangleright, \mathtt{FULL}, \mathbf{e}} &\otherwhen \segoff+\len{\mathbf{e}} \ge \Cmaxpackageexports \\                                                  
                                 \tup{\blacktriangleright, \segoff + \len{\mathbf{e}}, \mathbf{e} \append \mathbf{x}} &\otherwise                                                                      
                               \end{cases}                                                                                                                                                             
                             \end{aligned}$                                                                                                                                                            |
| 1-1(lr)2-2              |                                                                                                                                                                            |
| `machine` = 8           |                                                                                                                                                                            |
| $g = 10$                | $\begin{aligned}                                                                                                                                                           
                               \using \sq{p_O, p_Z, i} &= \registers\subrange{7}{3} \\                                                                                                                 
                               \using \mathbf{p} &= \begin{cases}                                                                                                                                      
                                 \memory\subrange{p_O}{p_Z} &\when \Nrange{p_O}{p_Z} \subseteq \readable{\memory} \\                                                                                   
                                 \error &\otherwise                                                                                                                                                    
                               \end{cases} \\                                                                                                                                                          
                               \using n &= \min(n \in \N, n \not\in \keys{\mathbf{m}}) \\                                                                                                              
                               \using \mathbf{u} &= \tup{\is{\ramSUBvalue}{[0, 0, \dots]},\is{\ramSUBaccess}{[\none, \none, \dots]}} \\                                                                
                               \tup{\execst', \registers'_7, \mathbf{m}} &\equiv \begin{cases}                                                                                                         
                                 \tup{\panic, \registers_7, \mathbf{m}} &\when \mathbf{p} = \error \\                                                                                                  
                                 \tup{\blacktriangleright, \mathtt{HUH}, \mathbf{m}} &\otherwhen \text{deblob}(\mathbf{p}) = \error \\                                                                 
                                 \tup{\blacktriangleright, n, \mathbf{m} \cup \set{\kv{n}{\tup{\mathbf{p}, \mathbf{u}, i}}} } &\otherwise \\                                                           
                               \end{cases} \\                                                                                                                                                          
                             \end{aligned}$                                                                                                                                                            |
| 1-1(lr)2-2              |                                                                                                                                                                            |
| `peek` = 9              |                                                                                                                                                                            |
| $g = 10$                | $\begin{aligned}                                                                                                                                                           
                               \using \sq{n, o, s, z} &= \registers\subrange{7}{4} \\                                                                                                                  
                               \tup{\execst', \registers'_7, {\memory}'} &\equiv \begin{cases}                                                                                                         
                                 \tup{\panic, \registers_7, {\memory}} &\when \Nrange{o}{z} \not\subseteq \writable[\memory] \\                                                                        
                                 \tup{\blacktriangleright, \mathtt{WHO}, {\memory}} &\otherwhen n \not\in \keys{\mathbf{m}} \\                                                                         
                                 \tup{\blacktriangleright, \mathtt{OOB}, {\memory}} &\otherwhen \Nrange{s}{z} \not\subseteq \readable{\mathbf{m}\subb{n}_\pgSUBram} \\                                 
                                 \tup{\blacktriangleright, \mathtt{OK}, {\memory}'} &\otherwise \\                                                                                                     
                                 \multicolumn{2}{l}{\where {\memory}' = {\memory}\exc {\memory}\subrange{o}{z} = (\mathbf{m}\subb{n}_\pgSUBram)\subrange{s}{z}}                                        
                               \end{cases} \\                                                                                                                                                          
                             \end{aligned}$                                                                                                                                                            |
| 1-1(lr)2-2              |                                                                                                                                                                            |
| `poke` = 10             |                                                                                                                                                                            |
| $g = 10$                | $\begin{aligned}                                                                                                                                                           
                               \using \sq{n, s, o, z} &= \registers\subrange{7}{4} \\                                                                                                                  
                               \tup{\execst', \registers'_7, \mathbf{m}'} &\equiv \begin{cases}                                                                                                        
                                 \tup{\panic, \registers_7, \mathbf{m}} &\when \Nrange{s}{z} \not\subseteq \readable[\memory] \\                                                                       
                                 \tup{\blacktriangleright, \mathtt{WHO}, \mathbf{m}} &\otherwhen n \not\in \keys{\mathbf{m}} \\                                                                        
                                 \tup{\blacktriangleright, \mathtt{OOB}, \mathbf{m}} &\otherwhen \Nrange{o}{z} \not\subseteq \writable{\mathbf{m}\subb{n}_\pgSUBram} \\                                
                                 \tup{\blacktriangleright, \mathtt{OK}, \mathbf{m}'}  &\otherwise \\                                                                                                   
                                 \multicolumn{2}{l}{\where \mathbf{m}' = \mathbf{m} \exc (\mathbf{m}'\subb{n}_\pgSUBram)\subrange{o}{z} = {\memory}\subrange{s}{z}}                                    
                               \end{cases} \\                                                                                                                                                          
                             \end{aligned}$                                                                                                                                                            |
| 1-1(lr)2-2              |                                                                                                                                                                            |
| `pages` = 11            |                                                                                                                                                                            |
| $g = 10$                | $\begin{aligned}                                                                                                                                                           
                               \using \sq{n, p, c, r} &= \registers\subrange{7}{4} \\                                                                                                                  
                               \using \mathbf{u} &= \begin{cases}                                                                                                                                      
                                 \mathbf{m}\subb{n}_\pgSUBram &\when n \in \keys{\mathbf{m}} \\                                                                                                        
                                 \error &\otherwise\\                                                                                                                                                  
                               \end{cases} \\                                                                                                                                                          
                               \using \mathbf{u}' &= \mathbf{u} \exc \begin{cases}                                                                                                                     
                                 (\mathbf{u}'_\ramSUBvalue)_{p\Cpvmpagesize\dots+c\Cpvmpagesize} = \begin{cases}                                                                                       
                                  \sq{0, 0, \dots} &\when r < 3 \\                                                                                                                                     
                                   (\mathbf{u}_\ramSUBvalue)_{p\Cpvmpagesize\dots+c\Cpvmpagesize} &\otherwise                                                                                          
                                 \end{cases} \\                                                                                                                                                        
                                 (\mathbf{u}'_\ramSUBaccess)\subrange{p}{c} = \begin{cases}                                                                                                            
                                  \sq{\none, \none, \dots} &\when r = 0 \\                                                                                                                             
                                  \sq{\mathrm{R}, \mathrm{R}, \dots} &\when r = 1 \vee r = 3 \\                                                                                                        
                                  \sq{\mathrm{W}, \mathrm{W}, \dots} &\when r = 2 \vee r = 4 \\                                                                                                        
                                 \end{cases}                                                                                                                                                           
                               \end{cases}\\                                                                                                                                                           
                               \tup{\registers'_7, \mathbf{m}'} &\equiv \begin{cases}                                                                                                                  
                                 \tup{\mathtt{WHO}, \mathbf{m}} &\when \mathbf{u} = \error \\                                                                                                          
                                 \tup{\mathtt{HUH}, \mathbf{m}} &\otherwhen r > 4 \vee p < 16 \vee p+c \ge \nicefrac{2^{32}}{\Cpvmpagesize} \\                                                         
                                 \tup{\mathtt{HUH}, \mathbf{m}} &\otherwhen r > 2 \wedge (\mathbf{u}_\ramSUBaccess)\subrange{p}{c} \ni \none \\                                                        
                                 \tup{\mathtt{OK}, \mathbf{m}'} &\otherwise\,,\ \where \mathbf{m}' = \mathbf{m} \exc \mathbf{m}'\subb{n}_\pgSUBram = \mathbf{u}' \\                                    
                               \end{cases} \\                                                                                                                                                          
                             \end{aligned}$                                                                                                                                                            |
| 1-1(lr)2-2              |                                                                                                                                                                            |
| `invoke` = 12           |                                                                                                                                                                            |
| $g = 10$                | $\begin{aligned}                                                                                                                                                           
                               \using \sq{n, o} &= \registers_{7, 8} \\                                                                                                                                
                               \using \tup{g, \mathbf{w}} &= \begin{cases}                                                                                                                             
                                 \tup{g, \mathbf{w}}: \encode[8]{g} \concat \encode[8]{\mathbf{w}} = {\memory}\subrange{o}{112} &\when \Nrange{o}{112} \subseteq \writable{{\memory}} \\               
                                 %\tup{\decode[8]{\memr\subrange{o}{8}}, \sq{\build{\decode[4]{\memr\subrange{o+8+8x}{8}}}{x \orderedin \Nmax{13}}}} &\when \Nrange{o}{60} \subset \writable_\mem} \\  
                                 \tup{\error, \error} &\otherwise                                                                                                                                      
                               \end{cases} \\                                                                                                                                                          
                               \using \tup{c, i', g', \mathbf{w}', \mathbf{u}'} &= \Psi(\mathbf{m}\subb{n}_\pgSUBcode, \mathbf{m}\subb{n}_\pgSUBpc, g, \mathbf{w}, \mathbf{m}\subb{n}_\pgSUBram)\\     
                               \using {\memory}^* &= {\memory}\exc {\memory}^*\subrange{o}{112} = \encode[8]{g'} \concat \encode[8]{\mathbf{w}'}\\                                                     
                               \using \mathbf{m}^* &= \mathbf{m} \exc \begin{cases}                                                                                                                    
                                 \mathbf{m}^*\subb{n}_\pgSUBram = \mathbf{u}'\\                                                                                                                        
                                 \mathbf{m}^*\subb{n}_\pgSUBpc = \begin{cases}                                                                                                                         
                                   i' + \text{skip}(\imath') + 1 &\when c \in \set{ \host } \times \pvmreg\\                                                                                           
                                   i' &\otherwise                                                                                                                                                      
                                 \end{cases}                                                                                                                                                           
                               \end{cases}\\                                                                                                                                                           
                               \tup{\execst', \registers'_7, \registers'_8, {\memory}', \mathbf{m}'} &\equiv \begin{cases}                                                                             
                                 \tup{\panic, \registers_7, \registers_8, {\memory}, \mathbf{m}} &\when g = \error \\                                                                                  
                                 \tup{\blacktriangleright, \mathtt{WHO}, \registers_8, {\memory}, \mathbf{m}} &\otherwhen n \not\in \mathbf{m} \\                                                      
                                 \tup{\blacktriangleright, \mathtt{HOST}, h, {\memory}^*, \mathbf{m}^*} &\otherwhen c = \host \times h \\                                                              
                                 \tup{\blacktriangleright, \mathtt{FAULT}, x, {\memory}^*, \mathbf{m}^*} &\otherwhen c = \fault \times x \\                                                            
                                 \tup{\blacktriangleright, \mathtt{OOG}, \registers_8, {\memory}^*, \mathbf{m}^*} &\otherwhen c = \oog \\                                                              
                                 \tup{\blacktriangleright, \mathtt{PANIC}, \registers_8, {\memory}^*, \mathbf{m}^*} &\otherwhen c = \panic \\                                                          
                                 \tup{\blacktriangleright, \mathtt{HALT}, \registers_8, {\memory}^*, \mathbf{m}^*} &\otherwhen c = \halt \\                                                            
                               \end{cases} \\                                                                                                                                                          
                             \end{aligned}$                                                                                                                                                            |
| 1-1(lr)2-2              |                                                                                                                                                                            |
| `expunge` = 13          |                                                                                                                                                                            |
| $g = 10$                | $\begin{aligned}                                                                                                                                                           
                               \using n &= \registers_7 \\                                                                                                                                             
                               \tup{\registers'_7, \mathbf{m}'} &\equiv \begin{cases}                                                                                                                  
                                 \tup{\mathtt{WHO}, \mathbf{m}} &\when n \not\in \keys{\mathbf{m}} \\                                                                                                  
                                 \tup{\mathbf{m}\subb{n}_\pgSUBpc, \mathbf{m} \setminus n} &\otherwise \\                                                                                              
                               \end{cases} \\                                                                                                                                                          
                             \end{aligned}$                                                                                                                                                            |

## Accumulate Functions

This defines a number of functions broadly of the form $(\gascounter' \in \signedgas, \registers' \in \sequence[13]{\pvmreg}, \memory', \tup{\imX', \mathbf{y}'}) = \Omega_\square(\gascounter \in \gas, \registers \in \sequence[13]{\pvmreg}, \memory \in \ram, \imXY \in \implications^2, \dots)$. Functions which have a result component which is equivalent to the corresponding argument may have said components elided in the description. Functions may also depend upon particular additional parameters.

Other than the gas-counter which is explicitly defined, elements of PVM state are each assumed to remain unchanged by the host-call unless explicitly specified. $$\begin{aligned}
  \gascounter' &\equiv \gascounter - g\\
  \tup{\execst', \registers', \memory', \imX', \mathbf{y}'} &\equiv \begin{cases}
    \tup{\oog, \registers, \memory, \mathbf{x}, \mathbf{y}} &\when \gascounter < g\\
    \tup{\blacktriangleright, \registers, \memory, \mathbf{x}, \mathbf{y}} \text{ except as indicated below} &\otherwise
  \end{cases}
\end{aligned}$$

|                   |                                                                                                                                                                                                                                                            |
|:------------------|:-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
|                   |                                                                                                                                                                                                                                                            |
| **Identifier**    |                                                                                                                                                                                                                                                            |
| **Gas usage**     |                                                                                                                                                                                                                                                            |
| 1-1(lr)2-2        |                                                                                                                                                                                                                                                            |
| `bless` = 14      |                                                                                                                                                                                                                                                            |
| $g = 10$          | $\begin{aligned}                                                                                                                                                                                                                                           
                         \using \sq{m, a, v, r, o, n} &= \registers\subrange{7}{6} \\                                                                                                                                                                                            
                         \using \mathbf{a} &= \begin{cases}                                                                                                                                                                                                                      
                           \decode[4]{\memory\subrange{a}{4\Ccorecount}} &\when \Nrange{a}{4\Ccorecount} \subseteq \readable{\memory} \\                                                                                                                                         
                           \error &\otherwise                                                                                                                                                                                                                                    
                         \end{cases} \\                                                                                                                                                                                                                                          
                         \using \mathbf{z} &= \begin{cases}                                                                                                                                                                                                                      
                           \set{\build{\kv{s}{g} \ \where \encode[4]{s} \concat \encode[8]{g} = \memory\subrange{o+12i}{12}}{i \in \Nmax{n}}} &\when \Nrange{o}{12n} \subseteq \readable{\memory} \\                                                                             
                           \error &\otherwise                                                                                                                                                                                                                                    
                         \end{cases} \\                                                                                                                                                                                                                                          
                         \tup{\execst', \registers'_7, (\imX'_\imSUBstate)_{\tup{\psSUBmanager, \psSUBassigners, \psSUBdelegator, \psSUBregistrar, \psSUBalwaysaccers}}} &= \begin{cases}                                                                                        
                           \tup{\panic, \registers_7, (\imX_\imSUBstate)_{\tup{\psSUBmanager, \psSUBassigners, \psSUBdelegator, \psSUBregistrar, \psSUBalwaysaccers}}} &\when \set{\mathbf{z}, \mathbf{a}} \ni \error \\                                                         
                           \tup{\blacktriangleright, \mathtt{WHO}, (\imX_\imSUBstate)_{\tup{\psSUBmanager, \psSUBassigners, \psSUBdelegator, \psSUBregistrar, \psSUBalwaysaccers}}} &\otherwhen \tup{m, v, r} \not\in \serviceid^3 \\                                            
                           \tup{\blacktriangleright, \mathtt{OK}, \tuple{m, \mathbf{a}, v, r, \mathbf{z}}} &\otherwise \\                                                                                                                                                        
                         \end{cases}                                                                                                                                                                                                                                             
                       \end{aligned}$                                                                                                                                                                                                                                            |
| 1-1(lr)2-2        |                                                                                                                                                                                                                                                            |
| `assign` = 15     |                                                                                                                                                                                                                                                            |
| $g = 10$          | $\begin{aligned}                                                                                                                                                                                                                                           
                         \using \sq{c, o, a} &= \registers\subrange{7}{3} \\                                                                                                                                                                                                     
                         \using \mathbf{q} &= \begin{cases}                                                                                                                                                                                                                      
                           \sq{\build{\memory\subrange{o + 32i}{32}}{i \orderedin \N_\Cauthqueuesize}} &\when \Nrange{o}{32\Cauthqueuesize} \subseteq \readable{\memory} \\                                                                                                      
                           \error &\otherwise                                                                                                                                                                                                                                    
                         \end{cases} \\                                                                                                                                                                                                                                          
                         \tup{\execst', \registers'_7, (\imX'_\imSUBstate)_\psSUBauthqueue\subb{c}, (\imX'_\imSUBstate)_\psSUBassigners\subb{c}} &= \begin{cases}                                                                                                                
                           \tup{\panic, \registers_7, (\imX_\imSUBstate)_\psSUBauthqueue\subb{c}, (\imX_\imSUBstate)_\psSUBassigners\subb{c}} &\when \mathbf{q} = \error \\                                                                                                      
                           \tup{\blacktriangleright, \mathtt{CORE}, (\imX_\imSUBstate)_\psSUBauthqueue\subb{c}, (\imX_\imSUBstate)_\psSUBassigners\subb{c}} &\otherwhen c \ge \Ccorecount \\                                                                                     
                           \tup{\blacktriangleright, \mathtt{HUH}, (\imX_\imSUBstate)_\psSUBauthqueue\subb{c}, (\imX_\imSUBstate)_\psSUBassigners\subb{c}} &\otherwhen \imX_\imSUBid \ne (\imX_\imSUBstate)_\psSUBassigners\subb{c}\\                                            
                           \tup{\blacktriangleright, \mathtt{WHO}, (\imX_\imSUBstate)_\psSUBauthqueue\subb{c}, (\imX_\imSUBstate)_\psSUBassigners\subb{c}} &\otherwhen a \not\in \serviceid \\                                                                                   
                           \tup{\blacktriangleright, \mathtt{OK}, \mathbf{q}, a} &\otherwise \\                                                                                                                                                                                  
                         \end{cases} \\                                                                                                                                                                                                                                          
                       \end{aligned}$                                                                                                                                                                                                                                            |
| 1-1(lr)2-2        |                                                                                                                                                                                                                                                            |
| `designate` = 16  |                                                                                                                                                                                                                                                            |
| $g = 10$          | $\begin{aligned}                                                                                                                                                                                                                                           
                         \using o &= \registers_7 \\                                                                                                                                                                                                                             
                         \using \mathbf{v} &= \begin{cases}                                                                                                                                                                                                                      
                           \sq{\build{\memory\subrange{o + 336i}{336}}{i \orderedin \valindex}} &\when \Nrange{o}{336\Cvalcount} \subseteq \readable{\memory} \\                                                                                                                 
                           \error &\otherwise                                                                                                                                                                                                                                    
                         \end{cases} \\                                                                                                                                                                                                                                          
                         \tup{\execst', \registers'_7, (\imX'_\imSUBstate)_\psSUBstagingset} &= \begin{cases}                                                                                                                                                                    
                           \tup{\panic, \registers_7, (\imX_\imSUBstate)_\psSUBstagingset} &\when \mathbf{v} = \error\\                                                                                                                                                          
                           \tup{\blacktriangleright, \mathtt{HUH}, (\imX_\imSUBstate)_\psSUBstagingset} &\otherwhen \imX_\imSUBid \ne (\imX_\imSUBstate)_\psSUBdelegator\\                                                                                                       
                           \tup{\blacktriangleright, \mathtt{OK}, \mathbf{v}} &\otherwise \\                                                                                                                                                                                     
                         \end{cases} \\                                                                                                                                                                                                                                          
                       \end{aligned}$                                                                                                                                                                                                                                            |
| 1-1(lr)2-2        |                                                                                                                                                                                                                                                            |
| `checkpoint` = 17 |                                                                                                                                                                                                                                                            |
| $g = 10$          | $\begin{aligned}                                                                                                                                                                                                                                           
                         \imY' &\equiv \imX \\                                                                                                                                                                                                                                   
                         \registers'_7 &\equiv \gascounter'                                                                                                                                                                                                                      
                       \end{aligned}$                                                                                                                                                                                                                                            |
| 1-1(lr)2-2        |                                                                                                                                                                                                                                                            |
| `new` = 18        |                                                                                                                                                                                                                                                            |
| $g = 10$          | $\begin{aligned}                                                                                                                                                                                                                                           
                         \using \sq{o, l, \saSUBminaccgas, \saSUBminmemogas, \saSUBgratis, i} &= \registers\subrange{7}{6} \\                                                                                                                                                    
                         \using \saSUBcodehash &= \begin{cases}                                                                                                                                                                                                                  
                           \memory\subrange{o}{32} &\when \Nrange{o}{32} \subseteq \readable{\memory} \wedge l \in \Nbits{32} \\                                                                                                                                                 
                           \error &\otherwise                                                                                                                                                                                                                                    
                         \end{cases}\\                                                                                                                                                                                                                                           
                         \using \mathbf{a} \in \serviceaccount \cup \set{\error} &= \begin{cases}                                                                                                                                                                                
                           \tup{                                                                                                                                                                                                                                                 
                             \saSUBcodehash,                                                                                                                                                                                                                                     
                             \is{\mathbf{\saSUBstorage}}{\emset},                                                                                                                                                                                                                
                             \is{\mathbf{\saSUBrequests}}{\set{\kv{\tup{c, l}}{\sq{}}}},                                                                                                                                                                                         
                             \is{\saSUBbalance}{\mathbf{a}_\saSUBminbalance},                                                                                                                                                                                                    
                             \saSUBminaccgas,                                                                                                                                                                                                                                    
                             \saSUBminmemogas,                                                                                                                                                                                                                                   
                             \is{\mathbf{\saSUBpreimages}}{\emset},                                                                                                                                                                                                              
                             \is{\saSUBcreated}{t},                                                                                                                                                                                                                              
                             \saSUBgratis,                                                                                                                                                                                                                                       
                             \is{\saSUBlastacc}{0},                                                                                                                                                                                                                              
                             \is{\saSUBparent}{\imX_\imSUBid}                                                                                                                                                                                                                    
                           } &\when c \ne \error \\                                                                                                                                                                                                                              
                           \error &\otherwise                                                                                                                                                                                                                                    
                         \end{cases} \\                                                                                                                                                                                                                                          
                         \using \mathbf{s} &= \imX_\imSUBself \exc \mathbf{s}_\saSUBbalance = (\imX_\imSUBself)_\saSUBbalance - \mathbf{a}_\saSUBminbalance \\                                                                                                                   
                         \tup{\execst', \registers'_7, \imX'_\imSUBnextfreeid, (\imX'_\imSUBstate)_\psSUBaccounts} &\equiv \begin{cases}                                                                                                                                         
                           \tup{\panic, \registers_7, \imX_\imSUBnextfreeid, (\imX_\imSUBstate)_\psSUBaccounts} &\when c = \error \\                                                                                                                                             
                           \tup{\blacktriangleright, \mathtt{HUH}, \imX_\imSUBnextfreeid, (\imX_\imSUBstate)_\psSUBaccounts} &\otherwhen f \ne 0 \wedge \imX_\imSUBid \ne (\imX_\imSUBstate)_\psSUBmanager \\                                                                    
                           \tup{\blacktriangleright, \mathtt{CASH}, \imX_\imSUBnextfreeid, (\imX_\imSUBstate)_\psSUBaccounts} &\otherwhen \mathbf{s}_\saSUBbalance < (\imX_\imSUBself)_\saSUBminbalance \\                                                                       
                           \tup{\blacktriangleright, \mathtt{FULL}, \imX_\imSUBnextfreeid, (\imX_\imSUBstate)_\psSUBaccounts} &\otherwhen \imX_\imSUBid = (\imX_\imSUBstate)_\psSUBregistrar \wedge i< \Cminpublicindex \wedge i\in \keys{(\imX_\imSUBstate)_\psSUBaccounts} \\  
                           \tup{\blacktriangleright, i, \imX_\imSUBnextfreeid, (\imX_\imSUBstate)_\psSUBaccounts \cup \mathbf{d}} &\otherwhen \imX_\imSUBid = (\imX_\imSUBstate)_\psSUBregistrar \wedge i< \Cminpublicindex \\                                                   
                           \multicolumn{2}{l}{\quad \where \mathbf{d} = \set{ \kv{i}{\mathbf{a}}, \kv{\imX_\imSUBid}{\mathbf{s}} }}\\                                                                                                                                            
                           \tup{\blacktriangleright, \imX_\imSUBnextfreeid, i^*, (\imX_\imSUBstate)_\psSUBaccounts \cup \mathbf{d}} &\otherwise \\                                                                                                                               
                           \multicolumn{2}{l}{\quad \where i^* = \text{check}(\Cminpublicindex + (\imX_\imSUBnextfreeid - \Cminpublicindex + 42) \bmod (2^{32} - \Cminpublicindex - 2^8))}\\                                                                                     
                           \multicolumn{2}{l}{\quad \also \mathbf{d} = \set{ \kv{\imX_\imSUBnextfreeid}{\mathbf{a}}, \kv{\imX_\imSUBid}{\mathbf{s}} }}\\                                                                                                                         
                         \end{cases} \\                                                                                                                                                                                                                                          
                       \end{aligned}$                                                                                                                                                                                                                                            |
| 1-1(lr)2-2        |                                                                                                                                                                                                                                                            |
| `upgrade` = 19    |                                                                                                                                                                                                                                                            |
| $g = 10$          | $\begin{aligned}                                                                                                                                                                                                                                           
                         \using \sq{o, g, m} &= \registers\subrange{7}{3} \\                                                                                                                                                                                                     
                         \using c &= \begin{cases}                                                                                                                                                                                                                               
                           \memory\subrange{o}{32} &\when \Nrange{o}{32} \subseteq \readable{\memory} \\                                                                                                                                                                         
                           \error &\otherwise                                                                                                                                                                                                                                    
                         \end{cases} \\                                                                                                                                                                                                                                          
                         \tup{\execst', \registers'_7, (\imX'_\imSUBself)_\saSUBcodehash, (\imX'_\imSUBself)_\saSUBminaccgas, (\imX'_\imSUBself)_\saSUBminmemogas} &\equiv \begin{cases}                                                                                         
                           \tup{\panic, \registers_7, (\imX_\imSUBself)_\saSUBcodehash, (\imX_\imSUBself)_\saSUBminaccgas, (\imX_\imSUBself)_\saSUBminmemogas} &\when c = \error \\                                                                                              
                           \tup{\blacktriangleright, \mathtt{OK}, c, g, m} &\otherwise \\                                                                                                                                                                                        
                         \end{cases}                                                                                                                                                                                                                                             
                       \end{aligned}$                                                                                                                                                                                                                                            |
| 1-1(lr)2-2        |                                                                                                                                                                                                                                                            |
| `transfer` = 20   |                                                                                                                                                                                                                                                            |
| $g = 10 + t$      | $\begin{aligned}                                                                                                                                                                                                                                           
                         \using \sq{\dxSUBdest, \dxSUBamount, l, o} &= \registers\subrange{7}{4},  \\                                                                                                                                                                            
                         \using \mathbf{d} &= (\imX_\imSUBstate)_\psSUBaccounts\\                                                                                                                                                                                                
                         \using \mathbf{t} \in \defxfer \cup \set{\error} &= \begin{cases}                                                                                                                                                                                       
                           \tup{                                                                                                                                                                                                                                                 
                             \is{\dxSUBsource}{\imX_\imSUBid},                                                                                                                                                                                                                   
                             \dxSUBdest,                                                                                                                                                                                                                                         
                             \dxSUBamount,                                                                                                                                                                                                                                       
                             \is{\dxSUBmemo}{\memory\subrange{o}{\Cmemosize}},                                                                                                                                                                                                   
                             \is{\dxSUBgas}{l}                                                                                                                                                                                                                                   
                           } &\when \Nrange{o}{\Cmemosize} \subseteq \readable{\memory} \\                                                                                                                                                                                       
                           \error &\otherwise                                                                                                                                                                                                                                    
                         \end{cases} \\                                                                                                                                                                                                                                          
                         \using b &= (\imX_\imSUBself)_\saSUBbalance - \dxSUBamount \\                                                                                                                                                                                           
                         \using \tup{c, t} &= \begin{cases}                                                                                                                                                                                                                      
                           \tup{\panic, 0} &\when \mathbf{t} = \error \\                                                                                                                                                                                                         
                           \tup{\mathtt{WHO}, 0} &\otherwhen \dxSUBdest \not \in \keys{\mathbf{d}} \\                                                                                                                                                                            
                           \tup{\mathtt{LOW}, 0} &\otherwhen l < \mathbf{d}[\dxSUBdest]_\saSUBminmemogas \\                                                                                                                                                                      
                           \tup{\mathtt{CASH}, 0} &\otherwhen b < (\imX_\imSUBself)_\saSUBminbalance \\                                                                                                                                                                          
                           \tup{\mathtt{OK}, l} &\otherwise                                                                                                                                                                                                                      
                         \end{cases} \\                                                                                                                                                                                                                                          
                         \tup{\execst', \registers'_7, \imX'_\imSUBxfers, (\imX'_\imSUBself)_\saSUBbalance} &\equiv \begin{cases}                                                                                                                                                
                           \tup{\panic, \registers_7, \imX_\imSUBxfers, (\imX_\imSUBself)_\saSUBbalance} &\when c = \panic \\                                                                                                                                                    
                           \tup{\blacktriangleright, c, \imX_\imSUBxfers, (\imX_\imSUBself)_\saSUBbalance} &\otherwhen c \ne \mathtt{OK} \\                                                                                                                                      
                           \tup{\blacktriangleright, \mathtt{OK}, \imX_\imSUBxfers \append \mathbf{t}, b} &\otherwise                                                                                                                                                            
                         \end{cases} \\                                                                                                                                                                                                                                          
                       \end{aligned}$                                                                                                                                                                                                                                            |
| 1-1(lr)2-2        |                                                                                                                                                                                                                                                            |
| `eject` = 21      |                                                                                                                                                                                                                                                            |
| $g = 10$          | $\begin{aligned}                                                                                                                                                                                                                                           
                         \using \sq{d, o} &= \registers_{7, 8} \\                                                                                                                                                                                                                
                         \using h &= \begin{cases}                                                                                                                                                                                                                               
                           \memory\subrange{o}{32} &\when \Nrange{o}{32} \subseteq \readable{\memory} \\                                                                                                                                                                         
                           \error &\otherwise                                                                                                                                                                                                                                    
                         \end{cases} \\                                                                                                                                                                                                                                          
                         \using \mathbf{d} &= \begin{cases}                                                                                                                                                                                                                      
                           (\imX_\imSUBstate)_\psSUBaccounts\subb{d} &\when d \ne \imX_\imSUBid \wedge d \in \keys{(\imX_\imSUBstate)_\psSUBaccounts} \\                                                                                                                         
                           \error &\otherwise \\                                                                                                                                                                                                                                 
                         \end{cases} \\                                                                                                                                                                                                                                          
                         \using l &= \max(81, \mathbf{d}_\saSUBoctets) - 81 \\                                                                                                                                                                                                   
                         \using \mathbf{s}' &= \imX_\imSUBself \exc \mathbf{s}'_\saSUBbalance = (\imX_\imSUBself)_\saSUBbalance + \mathbf{d}_\saSUBbalance \\                                                                                                                    
                         \tup{\execst', \registers'_7, (\imX'_\imSUBstate)_\psSUBaccounts} &\equiv \begin{cases}                                                                                                                                                                 
                           \tup{\panic, \registers_7, (\imX_\imSUBstate)_\psSUBaccounts} &\when h = \error \\                                                                                                                                                                    
                           \tup{\blacktriangleright, \mathtt{WHO}, (\imX_\imSUBstate)_\psSUBaccounts} &\otherwhen \mathbf{d} = \error \vee \mathbf{d}_\saSUBcodehash \ne \encode[32]{\imX_\imSUBid} \\                                                                           
                           \tup{\blacktriangleright, \mathtt{HUH}, (\imX_\imSUBstate)_\psSUBaccounts} &\otherwhen \mathbf{d}_\saSUBitems \ne 2 \vee \tup{h, l} \not\in \mathbf{d}_\saSUBrequests \\                                                                              
                           \tup{\blacktriangleright, \mathtt{OK}, (\imX_\imSUBstate)_\psSUBaccounts \setminus \set{d} \cup \set{ \kv{\imX_\imSUBid}{\mathbf{s}'} }} &\otherwhen \mathbf{d}_\saSUBrequests\subb{h, l} = \sq{x, y}, y < t - \Cexpungeperiod \\                     
                           \tup{\blacktriangleright, \mathtt{HUH}, (\imX_\imSUBstate)_\psSUBaccounts} &\otherwise \\                                                                                                                                                             
                         \end{cases} \\                                                                                                                                                                                                                                          
                       \end{aligned}$                                                                                                                                                                                                                                            |
| 1-1(lr)2-2        |                                                                                                                                                                                                                                                            |
| `query` = 22      |                                                                                                                                                                                                                                                            |
| $g = 10$          | $\begin{aligned}                                                                                                                                                                                                                                           
                         \using \sq{o, z} &= \registers_{7, 8} \\                                                                                                                                                                                                                
                         \using h &= \begin{cases}                                                                                                                                                                                                                               
                           \memory\subrange{o}{32} &\when \Nrange{o}{32} \subseteq \readable{\memory} \\                                                                                                                                                                         
                           \error &\otherwise                                                                                                                                                                                                                                    
                         \end{cases} \\                                                                                                                                                                                                                                          
                         \using \mathbf{a} &= \begin{cases}                                                                                                                                                                                                                      
                           (\imX_\imSUBself)_\saSUBrequests\subb{h, z} &\when \tup{h, z} \in \keys{(\imX_\imSUBself)_\saSUBrequests}\\                                                                                                                                           
                           \error &\otherwise\\                                                                                                                                                                                                                                  
                         \end{cases} \\                                                                                                                                                                                                                                          
                         \tup{\execst', \registers'_7, \registers'_8} &\equiv \begin{cases}                                                                                                                                                                                      
                           \tup{\panic, \registers_7, \registers_8} &\when h = \error \\                                                                                                                                                                                         
                           \tup{\blacktriangleright, \mathtt{NONE}, 0} &\otherwhen \mathbf{a} = \error \\                                                                                                                                                                        
                           \tup{\blacktriangleright, 0, 0} &\otherwhen \mathbf{a} = \sq{} \\                                                                                                                                                                                     
                           \tup{\blacktriangleright, 1 + 2^{32}x, 0} &\otherwhen \mathbf{a} = \sq{x} \\                                                                                                                                                                          
                           \tup{\blacktriangleright, 2 + 2^{32}x, y} &\otherwhen \mathbf{a} = \sq{x, y} \\                                                                                                                                                                       
                           \tup{\blacktriangleright, 3 + 2^{32}x, y + 2^{32}z} &\otherwhen \mathbf{a} = \sq{x, y, z} \\                                                                                                                                                          
                         \end{cases} \\                                                                                                                                                                                                                                          
                       \end{aligned}$                                                                                                                                                                                                                                            |
| 1-1(lr)2-2        |                                                                                                                                                                                                                                                            |
| `solicit` = 23    |                                                                                                                                                                                                                                                            |
| $g = 10$          | $\begin{aligned}                                                                                                                                                                                                                                           
                         \using \sq{o, z} &= \registers_{7, 8} \\                                                                                                                                                                                                                
                         \using h &= \begin{cases}                                                                                                                                                                                                                               
                           \memory\subrange{o}{32} &\when \Nrange{o}{32} \subseteq \readable{\memory} \\                                                                                                                                                                         
                           \error &\otherwise                                                                                                                                                                                                                                    
                         \end{cases} \\                                                                                                                                                                                                                                          
                         \using \mathbf{a} &= \begin{cases}                                                                                                                                                                                                                      
                           \imX_\imSUBself \text{ except: } &\\                                                                                                                                                                                                                  
                           \quad \mathbf{a}_\saSUBrequests\subb{\tup{h, z}} = \sq{} &\when h \ne \error \wedge \tup{h, z} \not\in \keys{(\imX_\imSUBself)_\saSUBrequests} \\                                                                                                     
                           \quad \mathbf{a}_\saSUBrequests\subb{\tup{h, z}} = (\imX_\imSUBself)_\saSUBrequests\subb{\tup{h, z}} \append t &\when (\imX_\imSUBself)_\saSUBrequests\subb{\tup{h, z}} = \sq{x, y} \\                                                                
                           \error &\otherwise\\                                                                                                                                                                                                                                  
                         \end{cases} \\                                                                                                                                                                                                                                          
                         \tup{\execst', \registers'_7, \imX'_\imSUBself} &\equiv \begin{cases}                                                                                                                                                                                   
                           \tup{\panic, \registers_7, \imX_\imSUBself} &\when h = \error \\                                                                                                                                                                                      
                           \tup{\blacktriangleright, \mathtt{HUH}, \imX_\imSUBself} &\otherwhen \mathbf{a} = \error \\                                                                                                                                                           
                           \tup{\blacktriangleright, \mathtt{FULL}, \imX_\imSUBself} &\otherwhen \mathbf{a}_\saSUBbalance < \mathbf{a}_\saSUBminbalance \\                                                                                                                       
                           \tup{\blacktriangleright, \mathtt{OK}, \mathbf{a}} &\otherwise \\                                                                                                                                                                                     
                         \end{cases} \\                                                                                                                                                                                                                                          
                       \end{aligned}$                                                                                                                                                                                                                                            |
| 1-1(lr)2-2        |                                                                                                                                                                                                                                                            |
| `forget` = 24     |                                                                                                                                                                                                                                                            |
| $g = 10$          | $\begin{aligned}                                                                                                                                                                                                                                           
                         \using \sq{o, z} &= \registers_{7, 8} \\                                                                                                                                                                                                                
                         \using h &= \begin{cases}                                                                                                                                                                                                                               
                           \memory\subrange{o}{32} &\when \Nrange{o}{32} \subseteq \readable{\memory} \\                                                                                                                                                                         
                           \error &\otherwise                                                                                                                                                                                                                                    
                         \end{cases} \\                                                                                                                                                                                                                                          
                         \using \mathbf{a} &= \begin{cases}                                                                                                                                                                                                                      
                           \imX_\imSUBself \text{ except:} &\\                                                                                                                                                                                                                   
                           \quad \left.                                                                                                                                                                                                                                          
                             \begin{aligned}                                                                                                                                                                                                                                     
                               \keys{\mathbf{a}_\saSUBrequests} &= \keys{(\imX_\imSUBself)_\saSUBrequests} \setminus \set{\tup{h, z}}\ ,\\[2pt]                                                                                                                                  
                               \keys{\mathbf{a}_\saSUBpreimages} &= \keys{(\imX_\imSUBself)_\saSUBpreimages} \setminus \set{h}                                                                                                                                                   
                             \end{aligned}                                                                                                                                                                                                                                       
                           \ \right\} &\when (\imX_\imSUBself)_\saSUBrequests\subb{h, z} \in \set{\sq{}, \sq{x, y}},\ y < t - \Cexpungeperiod \\                                                                                                                                 
                           \quad \mathbf{a}_\saSUBrequests\subb{h, z} = \sq{x, t} &\when (\imX_\imSUBself)_\saSUBrequests\subb{h, z} = \sq{x} \\                                                                                                                                 
                           \quad \mathbf{a}_\saSUBrequests\subb{h, z} = \sq{w, t} &\when (\imX_\imSUBself)_\saSUBrequests\subb{h, z} = \sq{x, y, w},\ y < t - \Cexpungeperiod \\                                                                                                 
                           \error &\otherwise\\                                                                                                                                                                                                                                  
                         \end{cases} \\                                                                                                                                                                                                                                          
                         \tup{\execst', \registers'_7, \imX'_\imSUBself} &\equiv \begin{cases}                                                                                                                                                                                   
                           \tup{\panic, \registers_7, \imX_\imSUBself} &\when h = \error \\                                                                                                                                                                                      
                           \tup{\blacktriangleright, \mathtt{HUH}, \imX_\imSUBself} &\otherwhen \mathbf{a} = \error \\                                                                                                                                                           
                           \tup{\blacktriangleright, \mathtt{OK}, \mathbf{a}} &\otherwise \\                                                                                                                                                                                     
                         \end{cases} \\                                                                                                                                                                                                                                          
                       \end{aligned}$                                                                                                                                                                                                                                            |
| 1-1(lr)2-2        |                                                                                                                                                                                                                                                            |
| `yield` = 25      |                                                                                                                                                                                                                                                            |
| $g = 10$          | $\begin{aligned}                                                                                                                                                                                                                                           
                         \using o &= \registers_7 \\                                                                                                                                                                                                                             
                         \using h &= \begin{cases}                                                                                                                                                                                                                               
                           \memory\subrange{o}{32} &\when \Nrange{o}{32} \subseteq \readable{\memory} \\                                                                                                                                                                         
                           \error &\otherwise                                                                                                                                                                                                                                    
                         \end{cases} \\                                                                                                                                                                                                                                          
                         \tup{\execst', \registers'_7, \imX'_\imSUByield} &\equiv \begin{cases}                                                                                                                                                                                  
                           \tup{\panic, \registers_7, \imX_\imSUByield} &\when h = \error \\                                                                                                                                                                                     
                           \tup{\blacktriangleright, \mathtt{OK}, h} &\otherwise \\                                                                                                                                                                                              
                         \end{cases} \\                                                                                                                                                                                                                                          
                       \end{aligned}$                                                                                                                                                                                                                                            |
| 1-1(lr)2-2        |                                                                                                                                                                                                                                                            |
| `provide` = 26    |                                                                                                                                                                                                                                                            |
| $g = 10$          | $\begin{aligned}                                                                                                                                                                                                                                           
                         \using \sq{o, z} &= \registers_{8, 9} \\                                                                                                                                                                                                                
                         \using \mathbf{d} &= (\imX_\imSUBstate)_\psSUBaccounts\\                                                                                                                                                                                                
                         \using s &= \begin{cases}                                                                                                                                                                                                                               
                           \imX_\imSUBid &\when \registers_7 = 2^{64} - 1 \\                                                                                                                                                                                                     
                           \registers_7 &\otherwise                                                                                                                                                                                                                              
                         \end{cases} \\                                                                                                                                                                                                                                          
                         \using \mathbf{i} &= \begin{cases}                                                                                                                                                                                                                      
                           \memory\subrange{o}{z} &\when \Nrange{o}{z} \subseteq \readable{\memory} \\                                                                                                                                                                           
                           \error &\otherwise                                                                                                                                                                                                                                    
                         \end{cases} \\                                                                                                                                                                                                                                          
                         \using \mathbf{a} &= \begin{cases}                                                                                                                                                                                                                      
                           \mathbf{d}[s] &\when s \in \keys{\mathbf{d}} \\                                                                                                                                                                                                       
                           \none &\otherwise                                                                                                                                                                                                                                     
                         \end{cases} \\                                                                                                                                                                                                                                          
                         \tup{\execst', \registers'_7, \imX'_\imSUBprovisions} &\equiv \begin{cases}                                                                                                                                                                             
                           \tup{\panic, \registers_7, \imX_\imSUBprovisions} &\when \mathbf{i} = \error \\                                                                                                                                                                       
                           \tup{\blacktriangleright, \mathtt{WHO}, \imX_\imSUBprovisions} &\otherwhen \mathbf{a} = \none \\                                                                                                                                                      
                           \tup{\blacktriangleright, \mathtt{HUH}, \imX_\imSUBprovisions} &\otherwhen \mathbf{a}_\saSUBrequests[\tup{\blake{\mathbf{i}}, z}] \ne \sq{} \\                                                                                                        
                           \tup{\blacktriangleright, \mathtt{HUH}, \imX_\imSUBprovisions} &\otherwhen \tup{s, \mathbf{i}} \in \imX_\imSUBprovisions \\                                                                                                                           
                           \tup{\blacktriangleright, \mathtt{OK}, \imX_\imSUBprovisions \cup \set{\tup{s, \mathbf{i}}}} &\otherwise \\                                                                                                                                           
                         \end{cases} \\                                                                                                                                                                                                                                          
                       \end{aligned}$                                                                                                                                                                                                                                            |

# Serialization Codec

## Common Terms

Our codec function $\mathcal{E}$ is used to serialize some term into a sequence of octets. We define the deserialization function $\fndecode$ as the inverse of $\mathcal{E}$ and able to decode some sequence into the original value. The codec is designed such that exactly one value is encoded into any given sequence of octets, and in cases where this is not desirable then we use special codec functions.

### Trivial Encodings

We define the serialization of $\none$ as the empty sequence: $$\encode{\none} \equiv \sq{}$$

We also define the serialization of an octet-sequence as itself: $$\encode{x \in \blob} \equiv x$$

We define anonymous tuples to be encoded as the concatenation of their encoded elements: $$\encode{\tup{a, b, \dots}} \equiv \encode{a} \concat \encode{b} \concat \dots$$

Passing multiple arguments to the serialization functions is equivalent to passing a tuple of those arguments. Formally: $$\begin{aligned}
  \encode{a, b, \dots} &\equiv \encode{\tup{a, b, \dots}}
\end{aligned}$$

We define general natural number serialization, able to encode naturals of up to $2^{64}$, as: $$\fnencode\colon\abracegroup{
    \Nbits{64} &\to \blob[1:9] \\
    x &\mapsto \begin{cases}
     \sq{0} &\when x = 0 \\
      \sq{2^8-2^{8-l} + \ffrac{x}{2^{8l}}} \concat \encode[l]{x \bmod 2^{8l}} &\when \exists l \in \N_8 : 2^{7l} \le x < 2^{7(l+1)} \\
     \sq{2^8-1} \concat \encode[8]{x} &\otherwhen x < 2^{64} \\
    \end{cases}
  }$$

### Sequence Encoding

We define the sequence serialization function $\encode{\sequence{T}}$ for any $T$ which is itself a subset of the domain of $\fnencode$. We simply concatenate the serializations of each element in the sequence in turn: $$\encode{[\mathbf{i}_0, \mathbf{i}_1, ...]} \equiv \encode{\mathbf{i}_0} \concat \encode{\mathbf{i}_1} \concat \dots$$

Thus, conveniently, fixed length octet sequences (hashes $\hash$ and its variants) have an identity serialization.

### Discriminator Encoding

When we have sets of heterogeneous items such as a union of different kinds of tuples or sequences of different length, we require a discriminator to determine the nature of the encoded item for successful deserialization. Discriminators are encoded as a natural and are encoded immediately prior to the item.

We generally use a *length discriminator* when serializing sequence terms which have variable length (general blobs $\blob$ or unbound numeric sequences $\sequence{\N}$) (though this is omitted in the case of fixed-length terms such as hashes $\hash$).[^19] In this case, we simply prefix the term its length prior to encoding. Thus, for some term $y \in \tup{x \in \blob, \dots}$, we would generally define its serialized form to be $\encode{\len{x}}\concat\encode{x}\concat\dots$. To avoid repetition of the term in such cases, we define the notation $\var{x}$ to mean that the term of value $x$ is variable in size and requires a length discriminator. Formally: $$\var{x} \equiv \tup{\len{x}, x}\text{ thus }\encode{\var{x}} \equiv \encode{\len{x}}\concat\encode{x}$$

We also define a convenient discriminator operator $\maybe{x}$ specifically for terms defined by some serializable set in union with $\none$ (generally denoted for some set $S$ as $\optional{S}$): $$\begin{aligned}
  \maybe{x} \equiv \begin{cases}
    0 &\when x = \none \\
    \tup{1, x} &\otherwise
  \end{cases}
\end{aligned}$$

### Bit Sequence Encoding

A sequence of bits $b \in \bitstring$ is a special case since encoding each individual bit as an octet would be very wasteful. We instead pack the bits into octets in order of least significant to most, and arrange into an octet stream. In the case of a variable length sequence, then the length is prefixed as in the general case. $$\begin{aligned}
  \encode{b \in \bitstring} &\equiv \begin{cases}
    \sq{} &\when b = \sq{} \\
    \sq{
      \sum\limits_{i=0}^{i < \min(8, \len{b})}
      b\sub{i} \cdot 2^i
    } \concat \encode{b\interval{8}{}} &\otherwise\\
  \end{cases}
\end{aligned}$$

### Dictionary Encoding

In general, dictionaries are placed in the Merkle trie directly (see appendix 27 for details). However, small dictionaries may reasonably be encoded as a sequence of pairs ordered by the key. Formally: $$\forall K, V: \encode{d \in \dictionary{K}{V}} \equiv
    \encode{
      \var{\sq{
        \orderby{k}{
          \build{
            \tup{\encode{k}, \encode{d\subb{k}}}
          }{
            k \in \keys{d}
          }
        }
      }}
    }$$

### Set Encoding

For any values which are sets and don’t already have a defined encoding above, we define the serialization of a set as the serialization of the set’s elements in proper order. Formally: $$\encode{\set{a, b, c, \dots}} \equiv \encode{a} \concat \encode{b} \concat \encode{c} \concat \dots \where a < b < c < \dots$$

### Fixed-length Integer Encoding

We first define the trivial natural number serialization functions which are subscripted by the number of octets of the final sequence. Values are encoded in a regular little-endian fashion. This is utilized for almost all integer encoding across the protocol. Formally: $$\fnencode[l \in \N]\colon\abracegroup{
    \Nbits{8l} &\to \blob[l] \\
    x &\mapsto \begin{cases}
      \sq{} &\when l = 0 \\
      \sq{x \bmod 256} \concat \encode[l - 1]{\floor{\frac{x}{256}}} &\otherwise
    \end{cases}
  }$$

For non-natural arguments, $\fnencode[l \in \N]$ corresponds to the definitions of $\fnencode$, except that recursive elements are made as $\fnencode[l]$ rather than $\fnencode$. Thus: $$\begin{aligned}
  \encode[l \in \N]{a, b, \dots} &\equiv \encode[l]{\tup{a, b, \dots}}\\
  \encode[l \in \N]{\tup{a, b, \dots}} &\equiv \encode[l]{a} \concat \encode[l]{b} \concat \dots\\
  \encode[l \in \N]{\sq{\mathbf{i}_0, \mathbf{i}_1, \dots}} &\equiv \encode[l]{\mathbf{i}_0} \concat \encode[l]{\mathbf{i}_1} \concat \dots
\end{aligned}$$

And so on.

## Block Serialization

A block $\block$ is serialized as a tuple of its elements in regular order, as implied in equations eq:block, eq:extrinsic and eq:header. For the header, we define both the regular serialization and the unsigned serialization $\fnencodeunsignedheader$. Formally:

$$\begin{aligned}
  \encode{\block} &= \encode{
    \header,
    \encodetickets{\xttickets},
    \encodepreimages{\xtpreimages},
    \encodeguarantees{\xtguarantees},
    \encodeassurances{\xtassurances},
    \encodedisputes{\xtdisputes}
  }
  \\
  \encodetickets{\xttickets} &= \encode{\var{\xttickets}} 
  \\
  \encodepreimages{\xtpreimages} &= \encode{
    \var{\sq{\build{
      \tup{\encode[4]{\xpSUBserviceindex}, \var{\xpSUBdata}}
    }{
      \tup{\xpSUBserviceindex, \xpSUBdata} \orderedin \xtpreimages}
    }}}
  \\
  \encodeguarantees{\xtguarantees} &= \encode{
    \var{\sq{\build{
      \tup{\xgSUBworkreport, \encode[4]{\xgSUBtimeslot}, \var{
        \sq{\build{
          \tup{\encode[2]{v}, s}
        }{
          \tup{v, s} \orderedin \xgSUBcredential
        }}
      }}
    }{
      \tup{\xgSUBworkreport, \xgSUBtimeslot, \xgSUBcredential} \orderedin \xtguarantees}
    }}}
  \\
  \encodeassurances{\xtassurances} &= \encode{
    \var{\sq{\build{
      \tup{\xaSUBanchor, \xaSUBavailabilities, \encode[2]{\xaSUBassurer}, \xaSUBsignature}
    }{
      \tup{\xaSUBanchor, \xaSUBavailabilities, \xaSUBassurer, \xaSUBsignature} \orderedin \xtassurances}
    }}}
  \\
  \encodedisputes{\tup{\mathbf{v}, \mathbf{c}, \mathbf{f}}} &= \encode{
    \var{\sq{\build{
      \tup{\xvSUBreporthash, \encode[4]{\xvSUBepochindex},
        \sq{\build{
          \tup{\xvjSUBvalidity, \encode[2]{\xvjSUBjudgeindex}, \xvjSUBsignature}
        }{
          \tup{\xvjSUBvalidity, \xvjSUBjudgeindex, \xvjSUBsignature} \orderedin \xvSUBjudgments
        }}
      }
    }{
      \tup{\xvSUBreporthash, \xvSUBepochindex, \xvSUBjudgments} \orderedin \mathbf{v}
    }}},
    \var{\mathbf{c}},
    \var{\mathbf{f}}
  }
  \\
  \encode{\header} &= \encode{
    \encodeunsignedheader{\header},
    \H_\SUBsealsig
  }
  \\
  \encodeunsignedheader{\header} &= \encode{
    \H_\SUBparent,
    \H_\SUBpriorstateroot,
    \H_\SUBextrinsichash,
    \encode[4]{\H_\SUBtimeslot},
    \maybe{\H_\SUBepochmark},
    \maybe{\H_\SUBwinnersmark},
    \encode[2]{\H_\SUBauthorindex},
    \H_\SUBvrfsig,
    \var{\H_\SUBoffendersmark}
  }
  \\
  \encode{\wcX \in \workcontext} &\equiv \encode{
    \wcX_\wcSUBanchorhash,
    \wcX_\wcSUBanchorpoststate,
    \wcX_\wcSUBanchoraccoutlog,
    \wcX_\wcSUBlookupanchorhash,
    \encode[4]{\wcX_\wcSUBlookupanchortime},
    \var{\wcX_\wcSUBprerequisites}
  }
  \\
  \encode{\asX \in \avspec} &\equiv \encode{
    \asX_\asSUBpackagehash,
    \encode[4]{\asX_\asSUBbundlelen},
    \asX_\asSUBerasureroot,
    \asX_\asSUBsegroot,
    \encode[2]{\asX_\asSUBsegcount}
  }
  \\
  \encode{\wdX \in \workdigest} &\equiv \encode{
    \encode[4]{\wdX_\wdSUBserviceindex},
    \wdX_\wdSUBcodehash,
    \wdX_\wdSUBpayloadhash,
    \encode[8]{\wdX_\wdSUBgaslimit},
    O\left(\wdX_\wdSUBresult\right),
    % These are variable length, since we never access them individually, digests
    % are never accessed directly by the PVM and space is at a premium here.
    \wdX_\wdSUBgasused,
    \wdX_\wdSUBimportcount,
    \wdX_\wdSUBxtcount,
    \wdX_\wdSUBxtsize,
    \wdX_\wdSUBexportcount
  }
  \\
  \encode{\wrX \in \workreport} &\equiv \encode{
    \wrX_\wrSUBavspec,
    \wrX_\wrSUBcontext,
    \wrX_\wrSUBcore,
    \wrX_\wrSUBauthorizer,
    \wrX_\wrSUBauthgasused,
    \var{\wrX_\wrSUBauthtrace},
    \var{\wrX_\wrSUBsrlookup},
    \var{\wrX_\wrSUBdigests}
  }
  \\
  \encode{\wpX \in \workpackage} &\equiv \encode{
    \encode[4]{\wpX_\wpSUBauthcodehost},
    \wpX_\wpSUBauthcodehash,
    \wpX_\wpSUBcontext,
    \var{\wpX_\wpSUBauthtoken},
    \var{\wpX_\wpSUBauthconfig},
    \var{\wpX_\wpSUBworkitems}
  }
  \\
  \encode{\wiX \in \workitem} &\equiv \encode{
    \encode[4]{\wiX_\wiSUBserviceindex},
    \wiX_\wiSUBcodehash,
    \encode[8]{\wiX_\wiSUBrefgaslimit},
    \encode[8]{\wiX_\wiSUBaccgaslimit},
    \encode[2]{\wiX_\wiSUBexportcount},
    \var{\wiX_\wiSUBpayload},
    \var{I^\#\left(\wiX_\wiSUBimportsegments\right)},
    \var{\sq{\build{
      \tup{h, \encode[4]{i}}
    }{
      \tup{h, i} \orderedin \wiX_\wiSUBextrinsics
    }}}
  }
  \\
  \encode{\stX \in \safroleticket} &\equiv \encode{
    \stX_\stSUBid,
    \stX_\stSUBentryindex
  }
  \\
  \encode[X]{\dxX \in \defxfer} &\equiv \encode{
    \encode[4]{\dxX_\dxSUBsource},
    \encode[4]{\dxX_\dxSUBdest},
    \encode[8]{\dxX_\dxSUBamount},
    \dxX_\dxSUBmemo,
    \encode[8]{\dxX_\dxSUBgas}
  }
  \\
  \encode[U]{\otX \in \operandtuple} &\equiv \encode{
    \otX_\otSUBpackagehash,
    \otX_\otSUBsegroot,
    \otX_\otSUBauthorizer,
    \otX_\otSUBpayloadhash,
    \otX_\otSUBgaslimit,
    O\left(\otX_\otSUBresult\right),
    \var{\otX_\otSUBauthtrace}
  }
  \\
  \encode{\aiX \in \accinput} &\equiv \begin{cases}
      \encode{0, \encode[U]{o}} &\when \aiX \in \operandtuple \\
      \encode{1, \encode[X]{o}} &\when \aiX \in \defxfer \\
  \end{cases}
  \\
  O\left(o \in \workerror \cup \blob\right) &\equiv \begin{cases}
    \tup{0, \var{o}} &\when o \in \blob \\
    1 &\when o = \infty \\
    2 &\when o = \panic \\
    3 &\when o = \badexports \\
    4 &\when o = \oversize \\
    5 &\when o = \token{BAD} \\
    6 &\when o = \token{BIG}
    \\
  \end{cases}
  \\
  I\left(\tup{
    h \in \hash \cup \hash^\boxplus,
    i \in \Nbits{15}
  }\right) &\equiv \begin{cases}
    \tup{h, \encode[2]{i}} &\when h \in \hash\\
    \tup{r, \encode[2]{i + 2^{15}}} &\when \exists r \in \hash, h = r^\boxplus\\
  \end{cases}
\end{aligned}$$

Note the use of $O$ above to succinctly encode the result of a work item and the slight transformations of $\xtguarantees$ and $\xtpreimages$ to take account of the fact their inner tuples contain variable-length sequence terms $a$ and $p$ which need length discriminators.

# State Merklization

The Merklization process defines a cryptographic commitment from which arbitrary information within state may be provided as being authentic in a concise and swift fashion. We describe this in two stages; the first defines a mapping from 31-octet sequences to (unlimited) octet sequences in a process called *state serialization*. The second forms a 32-octet commitment from this mapping in a process called *Merklization*.

## Serialization

The serialization of state primarily involves placing all the various components of $\thestate$ into a single mapping from 31-octet sequence *state-keys* to octet sequences of indefinite length. The state-key is constructed from a hash component and a chapter component, equivalent to either the index of a state component or, in the case of the inner dictionaries of $\accounts$, a service index.

We define the state-key constructor functions $C$ as: $$C\colon\abracegroup{
    \Nbits{8} \cup \tup{\Nbits{8}, \serviceid} \cup \tup{\serviceid, \blob} &\to \blob[31] \\
    i \in \Nbits{8} &\mapsto \sq{i, 0, 0, \dots} \\
    \tup{i, s \in \serviceid} &\mapsto \sq{i, n_0, 0, n_1, 0, n_2, 0, n_3, 0, 0, \dots}\ \where n = \encode[4]{s} \\
    \tup{s, h} &\mapsto \sq{n_0, a_0, n_1, a_1, n_2, a_2, n_3, a_3, a_4, a_5, \dots, a_{26}}\ \where n = \encode[4]{s}, a = \blake{h}
  }$$

The state serialization is then defined as the dictionary built from the amalgamation of each of the components. Cryptographic hashing ensures that there will be no duplicate state-keys given that there are no duplicate inputs to $C$. Formally, we define $T$ which transforms some state $\thestate$ into its serialized form: $$T(\thestate) \equiv \abracegroup{
    &&C(1) &\mapsto \encode{\sq{\build{\var{x}}{x \orderedin \authpool}}} \;, \\
    &&C(2) &\mapsto \encode{\authqueue} \;, \\
    &&C(3) &\mapsto \encode{
      \var{\sq{\build{
        \tup{\rhSUBheaderhash, \rhSUBaccoutlogsuperpeak, \rhSUBstateroot, \var{\rhSUBreportedpackagehashes}}
      }{
        \tup{\rhSUBheaderhash, \rhSUBaccoutlogsuperpeak, \rhSUBstateroot, \rhSUBreportedpackagehashes} \orderedin \recenthistory
      }}},
      \mmrencode{\accoutbelt}
    } \;, \\
    &&C(4) &\mapsto \encode{
      \pendingset,
      \epochroot,
      \abracegroupboth{
        0\ &\when \sealtickets \in \sequence[\Cepochlen]{\safroleticket}\\
        1\ &\when \sealtickets \in \sequence[\Cepochlen]{\bskey}\\
      },
      \sealtickets,
      \var{\ticketaccumulator}
    } \;, \\
    &&C(5) &\mapsto \encode{
      \var{\sqorderby{x}{x \in \goodset}},
      \var{\sqorderby{x}{x \in \badset}},
      \var{\sqorderby{x}{x \in \wonkyset}},
      \var{\sqorderby{x}{x \in \offenders}}
    } \;, \\
    &&C(6) &\mapsto \encode{\entropy} \;, \\
    &&C(7) &\mapsto \encode{\stagingset} \;, \\
    &&C(8) &\mapsto \encode{\activeset} \;, \\
    &&C(9) &\mapsto \encode{\previousset} \;, \\
    &&C(10) &\mapsto \encode{
      \sq{\build{
        \maybe{\tup{\rsSUBworkreport, \encode[4]{\rsSUBtimestamp}}}
      }{
        \tup{\rsSUBworkreport, \rsSUBtimestamp} \orderedin \reports
      }}
    } \;, \\
    &&C(11) &\mapsto \encode[4]{\thetime} \;, \\
    &&C(12) &\mapsto \encode{
      \encode[4]{\manager, \assigners, \delegator, \registrar},
      \alwaysaccers
    } \;, \\
    &&C(13) &\mapsto \encode{
      \encode[4]{\valstatsaccumulator, \valstatsprevious},
      \corestats,
      \servicestats
    } \;, \\
    &&C(14) &\mapsto \encode{
      \sq{\build{
        \var{\sq{\build{
          \tup{\mathbf{r}, \var{\mathbf{d}}}
        }{
          \tup{\mathbf{r}, \mathbf{d}} \orderedin \mathbf{i}
        }}}
      }{
        \mathbf{i} \orderedin \ready
      }}
    } \;, \\
    &&C(15) &\mapsto \encode{
      \sq{\build{\var{\mathbf{i}}}{\mathbf{i} \orderedin \accumulated}}
    } \;, \\
    &&C(16) &\mapsto \encode{
      \var{\sq{\build{\tup{\encode[4]{s}, \encode{h}}}{\tup{s, h} \orderedin \lastaccout}}}
    } \;, \\
    \forall \kv{s}{\saX} \in \accounts: &&C(255, s) &\mapsto \encode{
      0,
      \saX_\saSUBcodehash,
      \encode[8]{
        \saX_\saSUBbalance,
        \saX_\saSUBminaccgas,
        \saX_\saSUBminmemogas,
        \saX_\saSUBoctets,
        \saX_\saSUBgratis
      },
      \encode[4]{
        \saX_\saSUBitems,
        \saX_\saSUBcreated,
        \saX_\saSUBlastacc,
        \saX_\saSUBparent
      }
    } \;, \\
    \forall \kv{s}{\saX} \in \accounts, \kv{\mathbf{k}}{\mathbf{v}} \in \saX_\saSUBstorage:
      &&C(s, \encode[4]{2^{32}-1} \concat \mathbf{k}) &\mapsto \mathbf{v} \;, \\
    \forall \kv{s}{\saX} \in \accounts, \kv{h}{\mathbf{p}} \in \saX_\saSUBpreimages:
      &&C(s, \encode[4]{2^{32}-2} \concat h) &\mapsto \mathbf{p} \;, \\
    \forall \kv{s}{\saX} \in \accounts, \kv{\tup{h, l}}{\mathbf{t}} \in \saX_\saSUBrequests:
      &&C(s, \encode[4]{l} \concat h) &\mapsto \encode{
        \var{\sq{\build{\encode[4]{x}}{x \orderedin \mathbf{t}}}}
      }
  }$$

Note that most rows describe a single mapping between a key derived from a natural and the serialization of a state component. However, the final four rows each define sets of mappings since these items act over all service accounts and in the case of the final three rows, the keys of a nested dictionary with the service.

Also note that all non-discriminator numeric serialization in state is done in fixed-length according to the size of the term.

Finally, be aware that does not allow service storage keys to be directly inspected or enumerated. Thus the key values themselves are not required to be known by implementations, and only the Merklisation-ready serialisation is important, which is a fixed-size hash (alongside the service index and item marker). Implementations are free to use this fact in order to avoid storing the keys themselves.

## Merklization

With $T$ defined, we now define the rest of $\fnmerklizestate$ which primarily involves transforming the serialized mapping into a cryptographic commitment. We define this commitment as the root of the binary Patricia Merkle Trie with a format optimized for modern compute hardware, primarily by optimizing sizes to fit succinctly into typical memory layouts and reducing the need for unpredictable branching.

### Node Encoding and Trie Identification

We identify (sub-)tries as the hash of their root node, with one exception: empty (sub-)tries are identified as the zero-hash, $\zerohash$.

Nodes are fixed in size at 512 bit (64 bytes). Each node is either a branch or a leaf. The first bit discriminate between these two types.

In the case of a branch, the remaining 511 bits are split between the two child node hashes, using the last 255 bits of the 0-bit (left) sub-trie identity and the full 256 bits of the 1-bit (right) sub-trie identity.

Leaf nodes are further subdivided into embedded-value leaves and regular leaves. The second bit of the node discriminates between these.

In the case of an embedded-value leaf, the remaining 6 bits of the first byte are used to store the embedded value size. The following 31 bytes are dedicated to the state key. The last 32 bytes are defined as the value, filling with zeroes if its length is less than 32 bytes.

In the case of a regular leaf, the remaining 6 bits of the first byte are zeroed. The following 31 bytes store the state key. The last 32 bytes store the hash of the value.

Formally, we define the encoding functions $B$ and $L$: $$\begin{aligned}
  B&\colon\abracegroup{
    \tuple{\hash, \hash} &\to \bitstring[512]\\
    \tup{l, r} &\mapsto \sq{0} \concat \text{bits}(l)\interval{1}{} \concat \text{bits}(r)
  }\\
  L&\colon\abracegroup{
    \tuple{\blob[31], \blob} &\to \bitstring[512]\\
    \tup{k, v} &\mapsto \begin{cases}
      \sq{1, 0} \concat \text{bits}(\encode[1]{\len{v}})\interval{2}{} \concat \text{bits}(k) \concat \text{bits}(v) \concat \sq{0, 0, \dots} &\when \len{v} \le 32\\
      \sq{1, 1, 0, 0, 0, 0, 0, 0} \concat \text{bits}(k) \concat \text{bits}(\blake{v}) &\otherwise
    \end{cases}
  }
\end{aligned}$$

We may then define the basic Merklization function $\fnmerklizestate$ as: $$\begin{aligned}
  \merklizestate{\thestate} &\equiv M(\set{\build{\kv{\text{bits}(k)}{\tup{k, v}}}{\kv{k}{v} \in T(\thestate) }})\\
  M(d: \dictionary{\bitstring}{\tuple{\blob[31], \blob}}) &\equiv \begin{cases}
    \zerohash &\when \len{d} = 0\\
    \blake{\text{bits}^{-1}(L(k, v))} &\when \values{d} = \set{ \tup{k, v} }\\
    \blake{\text{bits}^{-1}(B(M(l), M(r)))} &\otherwise\\
    \multicolumn{2}{l}{\quad\where \forall b, p: \kv{b}{p} \in d \Leftrightarrow \kv{b\interval{1}{}}{p} \in \begin{cases}
      l &\when b_0 = 0 \\
      r &\when b_0 = 1
    \end{cases}
  }\end{cases}
\end{aligned}$$

# General Merklization

## Binary Merkle Trees

The Merkle tree is a cryptographic data structure yielding a hash commitment to a specific sequence of values. It provides $O(N)$ computation and $O(\log(N))$ proof size for inclusion. This *well-balanced* formulation ensures that the maximum depth of any leaf is minimal and that the number of leaves at that depth is also minimal.

The underlying function for our Merkle trees is the *node* function $N$, which accepts some sequence of blobs of some length $n$ and provides either such a blob back or a hash: $$N\colon\abracegroup{
    \tuple{\sequence{\blob[n]}, \blob \to \hash} &\to \blob[n] \cup \hash \\
    \tup{\mathbf{v}, H} &\mapsto \begin{cases}
      \zerohash &\when \len{\mathbf{v}} = 0 \\
      \mathbf{v}_0 &\when \len{\mathbf{v}} = 1 \\
      H(\token{\$node} \concat N(\mathbf{v}_{\dots\ceil{\nicefrac{\len{\mathbf{v}}}{2}}}, H) \concat N(\mathbf{v}_{\ceil{\nicefrac{\len{\mathbf{v}}}{2}}\dots}, H)) &\otherwise
    \end{cases}
  }\label{eq:merklenode}$$

The astute reader will realize that if our $\blob[n]$ happens to be equivalent $\hash$ then this function will always evaluate into $\hash$. That said, for it to be secure care must be taken to ensure there is no possibility of preimage collision. For this purpose we include the hash prefix $\token{\$node}$ to minimize the chance of this; simply ensure any items are hashed with a different prefix and the system can be considered secure.

We also define the *trace* function $T$, which returns each opposite node from top to bottom as the tree is navigated to arrive at some leaf corresponding to the item of a given index into the sequence. It is useful in creating justifications of data inclusion. $$T\colon\abracegroup{
    \tuple{\sequence{\blob[n]}, \Nmax{\len{\mathbf{v}}}, \blob \to \hash}\ &\to \sequence{\blob[n] \cup \hash}\\
    \tup{\mathbf{v}, i, H} &\mapsto \begin{cases}
     \sq{N(P^\bot(\mathbf{v}, i), H)} \concat T(P^\top(\mathbf{v}, i), i - P_I(\mathbf{v}, i), H) &\when \len{\mathbf{v}} > 1\\
      \sq{} &\otherwise\\
      \multicolumn{2}{l}{
        \begin{aligned}
          \quad \where P^s(\mathbf{v}, i) &\equiv \begin{cases}
            \mathbf{v}_{\dots\ceil{\nicefrac{\len{\mathbf{v}}}{2}}} &\when (i < \ceil{\nicefrac{\len{\mathbf{v}}}{2}}) = s\\
            \mathbf{v}_{\ceil{\nicefrac{\len{\mathbf{v}}}{2}}\dots} &\otherwise
          \end{cases}\\[4pt]
          \quad \also P_I(\mathbf{v}, i) &\equiv \begin{cases}
            0 &\when i < \ceil{\nicefrac{\len{\mathbf{v}}}{2}} \\
            \ceil{\nicefrac{\len{\mathbf{v}}}{2}} &\otherwise
          \end{cases}\\
        \end{aligned}
      }
    \end{cases}\\
  }$$

From this we define our other Merklization functions.

### Well-Balanced Tree

We define the well-balanced binary Merkle function as $\fnmerklizewb$: $$\fnmerklizewb\colon \abracegroup{
      \label{eq:simplemerkleroot}
      \tuple{\sequence{\blob}, \blob \to \hash} &\to \hash \\
      \tup{\mathbf{v}, H} &\mapsto \begin{cases}
        H(\mathbf{v}_0) &\when \len{\mathbf{v}} = 1 \\
        N(\mathbf{v}, H) &\otherwise
      \end{cases} \\
    }$$

This is suitable for creating proofs on data which is not much greater than 32 octets in length since it avoids hashing each item in the sequence. For sequences with larger data items, it is better to hash them beforehand to ensure proof-size is minimal since each proof will generally contain a data item.

Note: In the case that no hash function argument $H$ is supplied, we may assume Blake 2b.

### Constant-Depth Tree

We define the constant-depth binary Merkle function as $\fnmerklizecd$. We define two corresponding functions for working with subtree pages, $\fnmerklejustsubpath{x}$ and $\fnmerklesubtreepage{x}$. The latter provides a single page of leaves, themselves hashed, prefixed data. The former provides the Merkle path to a single page. Both assume size-aligned pages of size $2^x$ and accept page indices. $$\begin{aligned}
  \label{eq:constantdepthmerkleroot}
  \fnmerklizecd&\colon \abracegroup{
    \tuple{\sequence{\blob}, \blob \to \hash} &\to \hash\\
    \tup{\mathbf{v}, H} &\mapsto N(C(\mathbf{v}, H), H)
  }\\
  \label{eq:constantdepthsubtreemerklejust}
  \fnmerklejustsubpath{x}&\colon \abracegroup{
    \tuple{\sequence{\blob}, \Nmax{\len{\mathbf{v}}}, \blob \to \hash} &\to \sequence{\hash}\\
    \tup{\mathbf{v}, i, H} &\mapsto T(C(\mathbf{v}, H), 2^xi, H)_{\dots\max(0, \ceil{\log_2(\max(1, \len{\mathbf{v}})) - x})}
  }\\
  \label{eq:constantdepthsubtreemerkleleafpage}
  \fnmerklesubtreepage{x}&\colon \abracegroup{
    \tuple{\sequence{\blob}, \Nmax{\len{\mathbf{v}}}, \blob \to \hash} &\to \sequence{\hash}\\
    \tup{\mathbf{v}, i, H} &\mapsto \sq{\build{H(\token{\$leaf} \concat l)}{l \orderedin \mathbf{v}_{2^xi \dots \min(2^xi+2^x, \len{\mathbf{v}})}}}
  }
\end{aligned}$$

For the latter justification $\fnmerklejustsubpath{x}$ to be acceptable, we must assume the target observer also knows not merely the value of the item at the given index, but also all other leaves within its $2^x$ size subtree, given by $\fnmerklesubtreepage{x}$.

As above, we may assume a default value for $H$ of Blake 2b.

For justifications and Merkle root calculations, a constancy preprocessor function $C$ is applied which hashes all data items with a fixed prefix “leaf” and then pads the overall size to the next power of two with the zero hash $\zerohash$: $$C\colon\abracegroup{
    \tuple{\sequence{\blob}, \blob \to \hash} &\to \sequence{\hash}\\
    \tup{\mathbf{v}, H} &\mapsto \mathbf{v}' \ \where \abracegroup[\;]{
      \len{\mathbf{v}'} &= 2^{\ceil{\log_2(\max(1, \len{\mathbf{v}}))}}\\
      \mathbf{v}'\sub{i} &= \begin{cases}
        H(\token{\$leaf} \concat \mathbf{v}\sub{i}) &\when i < \len{\mathbf{v}}\\
        \zerohash &\otherwise \\
      \end{cases}
    }
  }$$

## Merkle Mountain Ranges and Belts

The Merkle Mountain Range (MMR) is an append-only cryptographic data structure which yields a commitment to a sequence of values. Appending to an MMR and proof of inclusion of some item within it are both $O(\log(N))$ in time and space for the size of the set.

We define a Merkle Mountain Range as being within the set $\sequence{\optional{\hash}}$, a sequence of peaks, each peak the root of a Merkle tree containing $2^i$ items where $i$ is the index in the sequence. Since we support set sizes which are not always powers-of-two-minus-one, some peaks may be empty, $\none$ rather than a Merkle root.

Since the sequence of hashes is somewhat unwieldy as a commitment, Merkle Mountain Ranges are themselves generally hashed before being published. Hashing them removes the possibility of further appending so the range itself is kept on the system which needs to generate future proofs.

We define the MMB append function $\fnmmrappend$ as: $$\begin{aligned}
    \label{eq:mmrappend}
    \fnmmrappend&\colon\deffunc{
      \tuple{\sequence{\optional{\hash}}, \hash, \blob\to\hash} &\to \sequence{\optional{\hash}}\\
      \tup{\mathbf{r}, l, H} &\mapsto P(\mathbf{r}, l, 0, H)
    }\\
    \where P&\colon\deffunc{
      \tuple{\sequence{\optional{\hash}}, \hash, \N, \blob\to\hash} &\to \sequence{\optional{\hash}}\\
      \tup{\mathbf{r}, l, n, H} &\mapsto \begin{cases}
        \mathbf{r} \append l &\when n \ge \len{\mathbf{r}}\\
        R(\mathbf{r}, n, l) &\when n < \len{\mathbf{r}} \wedge \mathbf{r}\sub{n} = \none\\
        P(R(\mathbf{r}, n, \none), H(\mathbf{r}\sub{n} \concat l), n + 1, H) &\otherwise
      \end{cases}
    }\\
    \also R&\colon\deffunc{
      \tuple{\sequence{T}, \N, T} &\to \sequence{T}\\
      \tup{\mathbf{s}, i, v} &\mapsto \mathbf{s}'\ \where \mathbf{s}' = \mathbf{s} \exc \mathbf{s}'\sub{i} = v
    }
  \end{aligned}$$

We define the MMR encoding function as $\fnmmrencode$: $$\fnmmrencode\colon\deffunc{
    \sequence{\optional{\hash}} &\to \blob \\
    \mathbf{b} &\mapsto \encode{\var{\sq{\build{\maybe{x}}{x \orderedin \mathbf{b}}}}}
  }$$

We define the MMR super-peak function as $\fnmmrsuperpeak$: $$\fnmmrsuperpeak\colon\deffunc{
    \sequence{\optional{\hash}} &\to \hash \\
    \mathbf{b} &\mapsto \begin{cases}
      \zerohash &\when \len{\mathbf{h}} = 0\\
      \mathbf{h}_0 &\when \len{\mathbf{h}} = 1\\
      \keccak{\token{\$peak} \concat \mmrsuperpeak{\mathbf{h}_{\dots\len{\mathbf{h}}-1}} \concat \mathbf{h}_{\len{\mathbf{h}}-1}} &\otherwise \\
      \multicolumn{2}{l}{\where \mathbf{h} = \sq{\build{h}{h \orderedin \mathbf{b}, h \ne \none}}}
    \end{cases}
  }$$

# Shuffling

The Fisher-Yates shuffle function is defined formally as: $$\label{eq:suffle}
  \forall T, l \in \N: \fnfyshuffle\colon\abracegroup{
    \tuple{\sequence[l]{T}, \sequence[l:]{\N}} &\to \sequence[l]{T}\\
    \tup{\mathbf{s}, \mathbf{r}} &\mapsto \begin{cases}
      \sq{\mathbf{s}_{\mathbf{r}_0 \bmod l}} \concat \fyshuffle{\mathbf{s}'\sub{\dots l-1}, \mathbf{r}\sub{1\dots}}\ \where \mathbf{s}' = \mathbf{s} \exc \mathbf{s'}\sub{\mathbf{r}_0 \bmod l} = \mathbf{s}\sub{l - 1} &\when \mathbf{s} \ne \sq{}\\
      \sq{} &\otherwise
    \end{cases}
  }$$

Since it is often useful to shuffle a sequence based on some random seed in the form of a hash, we provide a secondary form of the shuffle function $\fnfyshuffle$ which accepts a 32-byte hash instead of the numeric sequence. We define $\fnseqfromhash{}$, the numeric-sequence-from-hash function, thus: $$\begin{aligned}
  \forall l \in \N:\ \fnseqfromhash{l}&\colon\abracegroup{
    \hash &\to \sequence[l]{\Nbits{32}}\\
    h &\mapsto \sq{\build{
      \decode[4]{\blake{h \concat \encode[4]{\floor{\nicefrac{i}{8}}}}
      \sub{4i \bmod 32 \dots+4}}
    }{
      i \orderedin \N\sub{l}
    }}
  }\\
  \label{eq:sequencefromhash}
  \forall T, l \in \N:\ \fnfyshuffle&\colon\abracegroup{
    \tuple{\sequence[l]{T}, \hash} &\to \sequence[l]{T}\\
    \tup{\mathbf{s}, h} &\mapsto \fyshuffle{\mathbf{s}, \seqfromhash{l}{h}}
  }
\end{aligned}$$

# Bandersnatch VRF

The Bandersnatch curve is defined by .

The singly-contextualized Bandersnatch Schnorr-like signatures $\bssignature{k}{c}{m}$ are defined as a formulation under the *IETF* VRF template specified by (as IETF VRF) and further detailed by .

$$\begin{aligned}
  \bssignature{k \in \bskey}{c \in \hash}{m \in \blob} \subset \blob[96] &\equiv \set{\build{x}{x \in \blob[96], \text{verify}(k, c, m, x) = \top }}  \\
  \banderout{s \in \bssignature{k}{c}{m}} \in \hash &\equiv \text{output}(x \mid x \in \bssignature{k}{c}{m})\interval{}{32}
\end{aligned}$$

The singly-contextualized Bandersnatch RingVRF proofs $\bsringproof{r}{c}{m}$ are a zk-SNARK-enabled analogue utilizing the Pedersen VRF, also defined by and further detailed by .

$$\begin{aligned}
  \getringroot{\sequence{\bskey}} \in \ringroot &\equiv \text{commit}(\sequence{\bskey})  \\
  \bsringproof{r \in \ringroot}{c \in \hash}{m \in \blob} \subset \blob[784] &\equiv \set{\build{x}{x \in \blob[784], \text{verify}(r, c, m, x) = \top }}  \\
  \banderout{p \in \bsringproof{r}{c}{m}} \in \hash &\equiv \text{output}(x \mid x \in \bsringproof{r}{c}{m})\interval{}{32}
\end{aligned}$$

Note that in the case a key $\bskey$ has no corresponding Bandersnatch point when constructing the ring, then the Bandersnatch *padding point* as stated by should be substituted.

# Erasure Coding

The foundation of the data-availability and distribution system of is a systematic Reed-Solomon erasure coding function in GF($2^{16}$) of rate 342:1023, the same transform as done by the algorithm of . We use a little-endian $\blob[2]$ form of the 16-bit GF points with a functional equivalence given by $\fnencode[2]$. From this we may assume the encoding function $\fnerasurecode: \sequence[342]{\blob[2]} \to \sequence[1023]{\blob[2]}$ and the recovery function $\fnecrecover: \protoset{\tuple{\blob[2], \Nmax{1023}}}_{342} \to \sequence[342]{\blob[2]}$. Encoding is done by extrapolating a data blob of size 684 octets (provided in $\fnerasurecode$ here as 342 octet pairs) into 1,023 octet pairs. Recovery is done by collecting together any distinct 342 octet pairs, together with their indices, and transforming this into the original sequence of 342 octet pairs.

Practically speaking, this allows for the efficient encoding and recovery of data whose size is a multiple of 684 octets. Data whose length is not divisible by 684 must be padded (we pad with zeroes). We use this erasure-coding in two contexts within the protocol; one where we encode variable sized (but typically very large) data blobs for the Audit DA and block-distribution system, and the other where we encode much smaller fixed-size data *segments* for the Import DA system.

For the Import DA system, we deal with an input size of 4,104 octets resulting in data-parallelism of order six. We may attain a greater degree of data parallelism if encoding or recovering more than one segment at a time though for recovery, we may be restricted to requiring each segment to be formed from the same set of indices (depending on the specific algorithm).

## Blob Encoding and Recovery

We assume some data blob $\mathbf{d} \in \blob[684k], k \in \N$. This blob is split into a whole number of $k$ pieces, each a sequence of 342 octet pairs. Each piece is erasure-coded using $\fnerasurecode$ as above to give 1,023 octet pairs per piece.

The resulting matrix is grouped by its pair-index and concatenated to form 1,023 *chunks*, each of $k$ octet-pairs. Any 342 of these chunks may then be used to reconstruct the original data $\mathbf{d}$.

Formally we begin by defining two utility functions for splitting some large sequence into a number of equal-sized sub-sequences and for reconstituting such subsequences back into a single large sequence: $$\begin{aligned}
  \forall n \in \N, k \in \N :\ &\text{split}_{n}(\mathbf{d} \in \blob[kn]) \in \sequence[k]{\blob[n]} \equiv \sq{\mathbf{d}\subrange{0}{n}, \mathbf{d}\subrange{n}{n}, \cdots, \mathbf{d}\subrange{(k-1)n}{n}} \\
  \forall n \in \N, k \in \N :\ &\text{join}(\mathbf{c} \in \sequence[k]{\blob[n]}) \in \blob[kn] \equiv \mathbf{c}_0 \concat \mathbf{c}_1 \concat \dots
\end{aligned}$$

We define the transposition operator hence: $$\label{eq:transpose}
  {}^\text{T}\sq{\sq{\mathbf{x}_{0, 0}, \mathbf{x}_{0, 1}, \mathbf{x}_{0, 2}, \dots}, \sq{\mathbf{x}_{1, 0}, \mathbf{x}_{1, 1}, \dots}, \dots} \equiv \sq{\sq{\mathbf{x}_{0, 0}, \mathbf{x}_{1, 0}, \mathbf{x}_{2, 0}, \dots}, \sq{\mathbf{x}_{0, 1}, \mathbf{x}_{1, 1}, \dots}, \dots}$$

We may then define our erasure-code chunking function which accepts an arbitrary sized data blob whose length divides wholly into 684 octets and results in a sequence of 1,023 smaller blobs: $$\label{eq:erasurecoding}
  \fnerasurecode_{k \in \N}\colon\abracegroup{
    \blob[684k] &\to \sequence[1023]{\blob[2k]} \\
    \mathbf{d} &\mapsto \text{join}^\#({}^{\text{T}}\sq{\build{\erasurecode{\mathbf{p}}}{\mathbf{p} \orderedin {}^\text{T}\text{split}_{2}^\#(\text{split}_{2k}(\mathbf{d}))}})
  }$$

The original data may be reconstructed with any 342 of the 1,023 resultant items (along with their indices). If the original 342 items are known then reconstruction is just their concatenation. $$\label{eq:erasurecodinginv}
  \fnecrecover_{k \in \N}\colon\abracegroup{
    \protoset{\tuple{\blob[2k], \Nmax{1023}}}_{342} &\to \blob[684k] \\
    \mathbf{c} &\mapsto \begin{cases}
      \encode{\sq{\build{\mathbf{x}}{\tup{\mathbf{x}, i} \orderedin \sqorderby{i}{\tup{\mathbf{x}, i} \in \mathbf{c}}}}} &\when \set{\build{i}{\tup{\mathbf{x}, i} \in \mathbf{c}}} = \Nmax{342}\\
      \text{join}(\text{join}^\#({}^\text{T}\sq{
        \build{
          \ecrecover{{\set{\build{
           (\text{split}_{2}(\mathbf{x})\sub{p}, i)
          }{
            \tup{\mathbf{x}, i} \in \mathbf{c}
          }}}}
        }{
          p \in \Nmax{k}
        }
      })) &\text{always}\\
    \end{cases}
  }$$

Segment encoding/decoding may be done using the same functions albeit with a constant $k = 6$.

## Code Word representation

For the sake of brevity we call each octet pair a *word*. The code words (including the message words) are treated as element of $\finitefield_{2^{16}}$ finite field. The field is generated as an extension of $\finitefield_2$ using the irreducible polynomial: $$x^{16} + x^5 + x^3 + x^2 + 1$$

Hence: $$\finitefield_{2^{16}} \equiv \frac{\finitefield_2\subb{x}}{x^{16} + x^5 + x^3 + x^2 + 1}$$

We name the generator of $\frac{\finitefield_{2^{16}}}{\finitefield_2}$, the root of the above polynomial, $\authpool$ as such: $\finitefield_{2^{16}} = \finitefield_2(\authpool)$.

Instead of using the standard basis $\set{1, \authpool, \authpool^2, \dots, \authpool^{15}}$, we opt for a representation of $\finitefield_{2^{16}}$ which performs more efficiently for the encoding and the decoding process. To that aim, we name this specific representation of $\finitefield_{2^{16}}$ as $\tilde{\finitefield}_{2^{16}}$ and define it as a vector space generated by the following Cantor basis:

<div class="center">

|          |                                                                                                                                                                             |
|:---------|:----------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| $v_0$    | $1$                                                                                                                                                                         |
| $v_1$    | $\authpool^{15} + \authpool^{13} + \authpool^{11} + \authpool^{10} + \authpool^7                                                                                            
                + \authpool^6 + \authpool^3 + \authpool$                                                                                                                                 |
| $v_2$    | $\authpool^{13} + \authpool^{12} + \authpool^{11} + \authpool^{10} + \authpool^3                                                                                            
                + \authpool^2 + \authpool$                                                                                                                                               |
| $v_3$    | $\authpool^{12} + \authpool^{10} + \authpool^9 + \authpool^5 + \authpool^4 +                                                                                                
                \authpool^3 + \authpool^2 + \authpool$                                                                                                                                   |
| $v_4$    | $\authpool^{15} + \authpool^{14} + \authpool^{10} + \authpool^8 + \authpool^7 +                                                                                             
                \authpool$                                                                                                                                                               |
| $v_5$    | $\authpool^{15} + \authpool^{14} + \authpool^{13} + \authpool^{11} +                                                                                                        
                \authpool^{10} + \authpool^8 + \authpool^5 + \authpool^3 + \authpool^2 + \authpool$                                                                                      |
| $v_6$    | $\authpool^{15} + \authpool^{12} + \authpool^8 + \authpool^6 + \authpool^3 +                                                                                                
                \authpool^2$                                                                                                                                                             |
| $v_7$    | $\authpool^{14} + \authpool^4 + \authpool$                                                                                                                                  |
| $v_8$    | $\authpool^{14} + \authpool^{13} + \authpool^{11} + \authpool^{10} + \authpool^7                                                                                            
                + \authpool^4 + \authpool^3$                                                                                                                                             |
| $v_9$    | $\authpool^{12} + \authpool^7 + \authpool^6 + \authpool^4 + \authpool^3$                                                                                                    |
| $v_{10}$ | $\authpool^{14} + \authpool^{13} + \authpool^{11} + \authpool^9 + \authpool^6                                                                                               
                + \authpool^5 + \authpool^4 + \authpool$                                                                                                                                 |
| $v_{11}$ | $\authpool^{15} + \authpool^{13} + \authpool^{12} + \authpool^{11} + \authpool^8$                                                                                           |
| $v_{12}$ | $\authpool^{15} + \authpool^{14} + \authpool^{13} + \authpool^{12} + \authpool^{11} + \authpool^{10} + \authpool^8 + \authpool^7 + \authpool^5 + \authpool^4 + \authpool^3$ |
| $v_{13}$ | $\authpool^{15} + \authpool^{14} + \authpool^{13} + \authpool^{12} +                                                                                                        
                \authpool^{11} + \authpool^9 + \authpool^8 + \authpool^5 + \authpool^4 + \authpool^2$                                                                                    |
| $v_{14}$ | $\authpool^{15} + \authpool^{14} + \authpool^{13} + \authpool^{12} +                                                                                                        
                \authpool^{11} + \authpool^{10} + \authpool^9 + \authpool^8 + \authpool^5 + \authpool^4 +                                                                                
                \authpool^3$                                                                                                                                                             |
| $v_{15}$ | $\authpool^{15} + \authpool^{12} + \authpool^{11} + \authpool^8 + \authpool^4                                                                                               
                + \authpool^3 + \authpool^2 + \authpool$                                                                                                                                 |

</div>

Every message word $m\sub{i}=m_{i, 15} \ldots m\sub{i, 0}$ consists of 16 bits. As such it could be regarded as binary vector of length 16: $$m\sub{i} = \tup{m\sub{i, 0} \ldots m\sub{i, 15}}$$

Where $m_{i, 0}$ is the least significant bit of message word $m\sub{i}$. Accordingly we consider the field element $\tilde{m}\sub{i} = \sum^{15}_{j = 0} m\sub{i, j} v\sub{j}$ to represent that message word.

Similarly, we assign a unique index to each validator between 0 and 1,022 and we represent validator $i$ with the field element: $$\tilde{i} = \sum^{15}_{j = 0} i\sub{j} v\sub{j}$$

where $i = i_{15} \ldots i_0$ is the binary representation of $i$.

## The Generator Polynomial

To erasure code a message of 342 words into 1023 code words, we represent each message as a field element as described in previous section and we interpolate the polynomial $p(y)$ of maximum 341 degree which satisfies the following equalities: $$\begin{array}{l}
     p (\tilde{0}) = \widetilde{m_0}\\
     p (\tilde{1}) = \widetilde{m_1}\\
     \vdots\\
     p (\widetilde{341}) = \widetilde{m_{341}}
   \end{array}$$

After finding $p(y)$ with such properties, we evaluate $p$ at the following points: $$\begin{array}{l}
     \widetilde{r_{342}} : = p (\widetilde{342})\\
     \widetilde{r_{343}} : = p (\widetilde{343})\\
     \vdots\\
     \widetilde{r_{1022}} : = p (\widetilde{1022})
   \end{array}$$

We then distribute the message words and the extra code words among the validators according to their corresponding indices.

# Index of Notation

## Sets

### Regular Notation

$\finitefield$  
The set of finite fields.

$\N$  
The set of non-negative integers. Subscript denotes one greater than the maximum. See section 3.4.

$\N^+$  
The set of positive integers (not including zero).

$\balance$  
The set of balance values. Equivalent to $\Nbits{64}$. See equation eq:balance.

$\gas$  
The set of unsigned gas values. Equivalent to $\Nbits{64}$. See equation eq:gasregentry.

$\bloblength$  
The set of blob length values. Equivalent to $\Nbits{32}$. See section 3.4.

$\pvmreg$  
The set of register values. Equivalent to $\Nbits{64}$. See equation eq:gasregentry.

$\serviceid$  
The set from which service indices are drawn. Equivalent to $\Nbits{32}$. See section eq:serviceaccounts.

$\timeslot$  
The set of timeslot values. Equivalent to $\Nbits{32}$. See equation eq:time.

$\mathbb{Q}$  
The set of rational numbers. Unused.

$\mathbb{Z}$  
The set of integers. Subscript denotes range. See section 3.4.

$\signedgas$  
The set of signed gas values. Equivalent to $\mathbb{Z}_{-2^{63}\dots2^{63}}$. See equation eq:gasregentry.

### Custom Notation

$\dictionary{K}{V}$  
The set of dictionaries making a partial bijection of domain $k$ to range $v$. See section 3.5.

$\serviceaccount$  
The set of service $\mathbb{A}$ccounts. See equation eq:serviceaccount.

$\bitstring$  
The set of $\mathbb{b}$itstrings (Boolean sequences). Subscript denotes length. See section 3.7.

$\blob$  
The set of $\mathbb{B}$lobs (octet sequences). Subscript denotes length. See section 3.7.

$\blskey$  
The set of BLS public keys. A subset of $\blob[144]$. See section 3.8.2.

$\ringroot$  
The set of Bandersnatch ring roots. A subset of $\blob[144]$. See section 3.8 and appendix 29.

$\workcontext$  
The set of work-$\mathbb{C}$ontexts. See equation eq:workcontext. *Not used as the set of complex numbers.*

$\workdigest$  
The set of work-$\mathbb{D}$igests. See equation eq:workdigest.

$\workerror$  
The set of work execution $\mathbb{E}$rrors. See equation eq:workerror.

$\pvmguest$  
The set representing the state of a $\mathbb{G}$uest PVM instance. See equation eq:pvmguest.

$\hash$  
The set of 32-octet cryptographic values, equivalent to $\blob[32]$. Often a $\mathbb{H}$ash function’s result. See section 3.8.

$\edkey$  
The set of Ed25519 public keys. A subset of $\blob[32]$. See section 3.8.2.

$\bskey$  
The set of Bandersnatch public keys. A subset of $\blob[32]$. See section 3.8 and appendix 29.

$\operandtuple$  
The $\mathbb{I}$nformation concerning a single work-item once prepared as an operand for the accumulation function. See equation eq:operandtuple.

$\segment$  
The set of data segments, equivalent to $\blob[\Csegmentsize]$. See equation eq:segment.

$\valkey$  
The set of validator $\mathbb{K}$ey-sets. See equation eq:validatorkeys.

$\implications$  
The set representing implications of accumulation. See equation eq:implications.

$\ram$  
The set of PVM $\mathbb{M}$emory (RAM) states. See equation eq:pvmmemory.

$\workpackage$  
The set of work-$\mathbb{P}$ackages. See equation eq:workpackage.

$\workreport$  
The set of work-$\mathbb{R}$eports. See equation eq:workreport. *Note used for the set of real numbers.*

$\partialstate$  
The set representating a portion of overall $\mathbb{S}$tate, used during accumulation. See equation eq:partialstate.

$\safroleticket$  
The set of seal-key $\mathbb{T}$ickets. See equation eq:ticket.

$\readable{\memory}$  
The set of $\mathbb{V}$alidly readable indices for PVM RAM $\memory$. See appendix 23.

$\writable{\memory}$  
The set of $\mathbb{V}$alidly writable indices for PVM RAM $\memory$. See appendix 23.

$\edsignature{k}{m}$  
The set of $\mathbb{V}$alid Ed25519 signatures of the key $k$ and message $m$. A subset of $\blob[64]$. See section 3.8.

$\bssignature{k}{c}{m}$  
The set of $\mathbb{V}$alid Bandersnatch signatures of the public key $k$, context $c$ and message $m$. A subset of $\blob[96]$. See section 3.8.

$\bsringproof{r}{c}{m}$  
The set of $\mathbb{V}$alid Bandersnatch RingVRF proofs of the root $r$, context $c$ and message $m$. A subset of $\blob[784]$. See section 3.8.

$\workitem$  
The set of $\mathbb{W}$ork items. See equation eq:workitem.

$\defxfer$  
The set of deferred transfers. See equation eq:defxfer.

$\avspec$  
The set of availability specifications. See equation eq:avspec.

## Functions

$\accumulate$  
The accumulation functions (see section 12.2):

$\accone$  
The single-step accumulation function. See equation eq:accone.

$\accpar$  
The parallel accumulation function. See equation eq:accpar.

$\accseq$  
The full sequential accumulation function. See equation eq:accseq.

$\histlookup$  
The historical lookup function. See equation eq:historicallookup.

$\computereport$  
The work-report computation function. See equation eq:workdigestfunction.

$\transitionstate$  
The general state transition function. See equations eq:statetransition, eq:transitionfunctioncomposition.

$\Phi$  
The key-nullifier function. See equation eq:blacklistfilter.

$\Psi$  
The whole-program PVM machine state-transition function. See equation 23.

$\Psi_1$  
The single-step (PVM) machine state-transition function. See appendix 23.

$\Psi_A$  
The Accumulate PVM invocation function. See appendix 24.

$\Psi_H$  
The host-function invocation (PVM) with host-function marshalling. See appendix 23.

$\Psi_I$  
The Is-Authorized PVM invocation function. See appendix 24.

$\Psi_M$  
The marshalling whole-program PVM machine state-transition function. See appendix 23.

$\Psi_R$  
The Refine PVM invocation function. See appendix 24.

$\Omega$  
Virtual machine host-call functions. See appendix 24.

$\Omega_A$  
Assign-core host-call.

$\Omega_B$  
Empower-service host-call.

$\Omega_C$  
Checkpoint host-call.

$\Omega_D$  
Designate-validators host-call.

$\Omega_E$  
Export segment host-call.

$\Omega_F$  
Forget-preimage host-call.

$\Omega_G$  
Gas-remaining host-call.

$\Omega_H$  
Historical-lookup-preimage host-call.

$\Omega_I$  
Information-on-service host-call.

$\Omega_J$  
Eject-service host-call.

$\Omega_K$  
Kickoff-PVM host-call.

$\Omega_L$  
Lookup-preimage host-call.

$\Omega_M$  
Make-PVM host-call.

$\Omega_N$  
New-service host-call.

$\Omega_O$  
Poke-PVM host-call.

$\Omega_P$  
Peek-PVM host-call.

$\Omega_Q$  
Query-preimage host-call.

$\Omega_R$  
Read-storage host-call.

$\Omega_S$  
Solicit-preimage host-call.

$\Omega_T$  
Transfer host-call.

$\Omega_U$  
Upgrade-service host-call.

$\Omega_W$  
Write-storage host-call.

$\Omega_X$  
Expunge-PVM host-call.

$\Omega_Y$  
Fetch data host-call.

$\Omega_Z$  
Pages inner-PVM memory host-call.

$\Omega_\Taurus$  
Yield accumulation trie result host-call.

$\Omega_\Aries$  
Provide preimage host-call.

## Utilities, Externalities and Standard Functions

$\fnmmrappend(\dots)$  
The Merkle mountain range append function. See equation eq:mmrappend.

$\fnoctetstobits\sub{n}(\dots)$  
The octets-to-bits function for $n$ octets. Superscripted ${}^{-1}$ to denote the inverse. See equation eq:bitsfunc.

$\fnerasurecode\sub{n}(\dots)$  
The erasure-coding functions for $n$ chunks. See equation eq:erasurecoding.

$\encode{\dots}$  
The octet-sequence encode function. Superscripted ${}^{-1}$ to denote the inverse. See appendix 25.

$\fnfyshuffle(\dots)$  
The Fisher-Yates shuffle function. See equation eq:suffle.

$\blake{\dots}$  
The Blake 2b 256-bit hash function. See section 3.8.

$\keccak{\dots}$  
The Keccak 256-bit hash function. See section 3.8.

$\fnmerklejustsubpath{x}$  
The justification path to a specific $2^x$ size page of a constant-depth Merkle tree. See equation eq:constantdepthsubtreemerklejust.

$\keys{\dots}$  
The domain, or set of keys, of a dictionary. See section 3.5.

$\fnmerklesubtreepage{x}$  
The $2^x$ size page function for a constant-depth Merkle tree. See equation eq:constantdepthsubtreemerkleleafpage.

$\merklizecd{\dots}$  
The constant-depth binary Merklization function. See appendix 27.

$\merklizewb{\dots}$  
The well-balanced binary Merklization function. See appendix 27.

$\merklizestate{\dots}$  
The state Merklization function. See appendix 26.

$\getringroot{\dots}$  
The Bandersnatch ring root function. See section 3.8 and appendix 29.

$\zeropad{n}{\dots}$  
The octet-array zero-padding function. See equation eq:zeropadding.

$\seqfromhash{}{\dots}$  
The numeric-sequence-from-hash function. See equation eq:sequencefromhash.

$\ecrecover{\dots}$  
The group of erasure-coding piece-recovery functions. See equation eq:erasurecodinginv.

$\edsigndata{k}{\dots}$  
The Ed25519 signing function. See section 3.8.

$\blssigndata{k}{\dots}$  
The BLS signing function. See section 3.8.

$\wallclock$  
The current time expressed in seconds after the start of the Common Era. See section 4.4.

$\subifnone{\dots}$  
The substitute-if-nothing function. See equation eq:substituteifnothing.

$\values{\dots}$  
The range, or set of values, of a dictionary or sequence. See section 3.5.

$\sext{n}{\dots}$  
The signed-extension function for a value in $\Nbits{8n}$. See equation eq:signedextension.

$\banderout{\dots}$  
The alias/output/entropy function of a Bandersnatch VRF signature/proof. See section 3.8 and appendix 29.

$\fntosigned{n}(\dots)$  
The into-signed function for a value in $\Nbits{8n}$. Superscripted with ${}^{-1}$ to denote the inverse. See equation eq:signedfunc.

## Values

### Block-context Terms

These terms are all contextualized to a single block. They may be superscripted with some other term to alter the context and reference some other block.

$\ancestors$  
The ancestor set of the block. See equation eq:ancestors.

$\block$  
The block. See equation eq:block.

$\extrinsic$  
The block extrinsic. See equation eq:extrinsic.

$\accoutcommitment{v}$  
The BEEFY signed commitment of validator $v$. See equation eq:accoutsignedcommitment.

$\reporters$  
The set of Ed25519 guarantor keys who made a work-report. See equation eq:guarantorsig.

$\header$  
The block header. See equation eq:header.

$\accumulationstatistics$  
The sequence of work-reports which were accumulated this in this block. See equations eq:accumulationstatisticsspec and eq:accumulationstatisticsdef.

$\guarantorassignments$  
The mapping from cores to guarantor keys. See section 11.3.

$\guarantorassignmentsunderlastrotation$  
The mapping from cores to guarantor keys for the previous rotation. See section 11.3.

$\justbecameavailable$  
The sequence of work-reports which have now become available and ready for accumulation. See equation eq:availableworkreports.

$\isticketed$  
The ticketed condition, true if the block was sealed with a ticket signature rather than a fallback. See equations eq:ticketconditiontrue and eq:ticketconditionfalse.

$\isaudited$  
The audit condition, equal to $\top$ once the block is audited. See section 17.

Without any superscript, the block is assumed to the block being imported or, if no block is being imported, the head of the best chain (see section 19). Explicit block-contextualizing superscripts include:

$\block^\natural$  
The latest finalized block. See equation 19.

$\block^\flat$  
The block at the head of the best chain. See equation 19.

### State components

Here, the prime annotation indicates posterior state. Individual components may be identified with a letter subscript.

$\authpool$  
The core $\authpool$uthorizations pool. See equation eq:authstatecomposition.

$\recent$  
Log of recent activity. See equation eq:recentspec.

$\recenthistory$  
Information on the most recent blocks. See equation eq:recenthistoryspec.

$\accoutbelt$  
The Merkle mountain belt for accumulating Accumulation outputs. See equations eq:accoutbeltspec and eq:accoutbeltdef.

$\safrole$  
State concerning Safrole. See equation eq:consensusstatecomposition.

$\ticketaccumulator$  
The sealing lottery ticket accumulator. See equation eq:ticketaccumulatorsealticketsspec.

$\pendingset$  
The keys for the validators of the next epoch, equivalent to those keys which constitute $\epochroot$. See equation eq:validatorkeys.

$\sealtickets$  
The sealing-key sequence of the current epoch. See equation eq:ticketaccumulatorsealticketsspec.

$\epochroot$  
The Bandersnatch root for the current epoch’s ticket submissions. See equation eq:epochrootspec.

$\accountspre$  
The (prior) state of the service accounts. See equation eq:serviceaccounts.

$\accountspostacc$  
The post-accumulation, pre-preimage integration intermediate state. See equation eq:accountspostaccdef.

$\entropy$  
The entropy accumulator and epochal randomness. See equation eq:entropycomposition.

$\stagingset$  
The validator keys and metadata to be drawn from next. See equation eq:validatorkeys.

$\activeset$  
The validator keys and metadata currently active. See equation eq:validatorkeys.

$\previousset$  
The validator keys and metadata which were active in the prior epoch. See equation eq:validatorkeys.

$\reports$  
The pending reports, per core, which are being made available prior to accumulation. See equation eq:reportingstate.

$\reportspostjudgement$  
The post-judgment, pre-guarantees-extrinsic intermediate state. See equation eq:removenonpositive.

$\reportspostguarantees$  
The post-guarantees-extrinsic, pre-assurances-extrinsic, intermediate state. See equation eq:reportspostguaranteesdef.

$\thestate$  
The overall state of the system. See equations eq:statetransition, eq:statecomposition.

$\thetime$  
The most recent block’s timeslot. See equation eq:timeslotindex.

$\authqueue$  
The authorization queue. See equation eq:authstatecomposition.

$\disputes$  
Past judgments on work-reports and validators. See equation eq:disputesspec.

$\badset$  
Work-reports judged to be incorrect. See equation eq:badsetdef.

$\goodset$  
Work-reports judged to be correct. See equation eq:goodsetdef.

$\wonkyset$  
Work-reports whose validity is judged to be unknowable. See equation eq:wonkysetdef.

$\offenders$  
Validators who made a judgment found to be incorrect. See equation eq:offendersdef.

$\privileges$  
The privileged service indices. See equation eq:privilegesspec.

$\manager$  
The index of the blessed service. See equation eq:accountspostaccdef.

$\assigners$  
The indices of the services able to assign each core’s authorizer queue. See equation eq:accountspostaccdef.

$\delegator$  
The index of the designate service. See equation eq:accountspostaccdef.

$\registrar$  
The index of the registrar service. See equation eq:accountspostaccdef.

$\alwaysaccers$  
The always-accumulate service indices and their basic gas allowance. See equation eq:accountspostaccdef.

$\activity$  
The activity statistics for the validators. See equation eq:activityspec.

$\ready$  
The accumulation queue. See equation eq:readyspec.

$\accumulated$  
The accumulation history. See equation eq:accumulatedspec.

$\lastaccout$  
The most recent Accumulation outputs. See equations eq:lastaccoutspec and eq:finalstateaccumulation.

### Virtual Machine components

$\varepsilon$  
The exit-reason resulting from all machine state transitions.

$\nu$  
The immediate values of an instruction.

$\memory$  
The memory sequence; a member of the set $\ram$.

$\gascounter$  
The gas counter.

$\registers$  
The registers.

$\zeta$  
The instruction sequence.

$\varpi$  
The sequence of basic blocks of the program.

$\imath$  
The instruction counter.

### Constants

$\Ctrancheseconds = 8$  
The period, in seconds, between audit tranches. See section 17.3.

$\Citemdeposit = 10$  
The additional minimum balance required per item of elective service state. See equation eq:deposits.

$\Cbytedeposit = 1$  
The additional minimum balance required per octet of elective service state. See equation eq:deposits.

$\Cbasedeposit = 100$  
The basic minimum balance which all services require. See equation eq:deposits.

$\Ccorecount = 341$  
The total number of cores.

$\Cexpungeperiod = 19,200$  
The period in timeslots after which an unreferenced preimage may be expunged. See `eject` definition in section 24.7.

$\Cepochlen = 600$  
The length of an epoch in timeslots. See section 4.8.

$\Cauditbiasfactor = 2$  
The audit bias factor, the expected number of additional validators who will audit a work-report in the following tranche for each no-show in the previous. See equation eq:latertranches.

$\Creportaccgas = 10,000,000$  
The gas allocated to invoke a work-report’s Accumulation logic.

$\Cpackageauthgas = 50,000,000$  
The gas allocated to invoke a work-package’s Is-Authorized logic.

$\Cpackagerefgas = 5,000,000,000$  
The gas allocated to invoke a work-package’s Refine logic.

$\Cblockaccgas = 3,500,000,000$  
The total gas allocated across for all Accumulation. Should be no smaller than $\Creportaccgas\cdot\Ccorecount + \sum_{g \in \values{\alwaysaccers}}(g)$.

$\Crecenthistorylen = 8$  
The size of recent history, in blocks. See equation eq:recenthistorydef.

$\Cmaxpackageitems = 16$  
The maximum amount of work items in a package. See equations eq:workreport and eq:workpackage.

$\Cmaxreportdeps = 8$  
The maximum sum of dependency items in a work-report. See equation eq:limitreportdeps.

$\Cmaxblocktickets = 16$  
The maximum number of tickets which may be submitted in a single extrinsic. See equation eq:enforceticketlimit.

$\Cmaxlookupanchorage = 14,400$  
The maximum age in timeslots of the lookup anchor. See equation eq:limitlookupanchorage.

$\Cticketentries = 2$  
The number of ticket entries per validator. See equation eq:ticketsextrinsic.

$\Cauthpoolsize = 8$  
The maximum number of items in the authorizations pool. See equation eq:authstatecomposition.

$\Cslotseconds = 6$  
The slot period, in seconds. See equation 4.8.

$\Cauthqueuesize = 80$  
The number of items in the authorizations queue. See equation eq:authstatecomposition.

$\Crotationperiod = 10$  
The rotation period of validator-core assignments, in timeslots. See sections 11.3 and 11.4.

$\Cminpublicindex = 2^{16}$  
The minimum public service index. Services of indices below these may only be created by the Registrar. See equation eq:newserviceindex.

$\Cmaxpackagexts = 128$  
The maximum number of extrinsics in a work-package. See equation eq:limitworkpackagebandwidth.

$\Cassurancetimeoutperiod = 5$  
The period in timeslots after which reported but unavailable work may be replaced. See equation eq:reportspostguaranteesdef.

$\Cvalcount = 1023$  
The total number of validators.

$\Cmaxauthcodesize = 64,000$  
The maximum size of is-authorized code in octets. See equation eq:isauthinvocation.

$\Cmaxbundlesize = 13,791,360$  
The maximum size of the concatenated variable-size blobs, extrinsics and imported segments of a work-package, in octets. See equation eq:checkextractsize.

$\Cmaxservicecodesize = 4,000,000$  
The maximum size of service code in octets. See equations eq:refinvocation, eq:accinvocation & eq:onxferinvocation.

$\Cecpiecesize = 684$  
The basic size of erasure-coded pieces in octets. See equation eq:erasurecoding.

$\Csegmentsize = \Csegmentecpieces\Cecpiecesize = 4104$  
The size of a segment in octets. See section 14.2.1.

$\Csegmentfootprint = \Csegmentsize + 32\ceil{\log_2(\Cmaxpackageimports)} = 4488$  
The additional footprint in the Audits DA of a single imported segment. See equation eq:segmentfootprint.

$\Cmaxpackageimports = 3,072$  
The maximum number of imports in a work-package. See equation eq:limitworkpackagebandwidth.

$\Csegmentecpieces = 6$  
The number of erasure-coded pieces in a segment.

$\Cmaxreportvarsize = 48\cdot2^{10}$  
The maximum total size of all unbounded blobs in a work-report, in octets. See equation eq:limitworkreportsize.

$\Cmemosize = 128$  
The size of a transfer memo in octets. See equation eq:defxfer.

$\Cmaxpackageexports = 3,072$  
The maximum number of exports in a work-package. See equation eq:limitworkpackagebandwidth.

$\mathsf{X}$  
Context strings, see below.

$\Cepochtailstart = 500$  
The number of slots into an epoch at which ticket-submission ends. See sections 6.5, 6.6 and 6.7.

$\Cpvmdynaddralign = 2$  
The PVM dynamic address alignment factor. See equation eq:jumptablealignment.

$\Cpvminitinputsize = 2^{24}$  
The standard PVM program initialization input data size. See equation 23.7.

$\Cpvmpagesize = 2^{12}$  
The PVM memory page size. See equation eq:pvmmemory.

$\Cpvminitzonesize = 2^{16}$  
The standard PVM program initialization zone size. See section 23.7.

### Signing Contexts

$\Xavailable = \token{\$jam\_available}$  
*Ed25519* Availability assurances. See equation eq:assurancesig.

$\Xbeefy = \token{\$jam\_beefy}$  
*BLS* Accumulate-result-root-MMR commitment. See equation eq:accoutsignedcommitment.

$\Xentropy = \token{\$jam\_entropy}$  
On-chain entropy generation. See equation eq:vrfsigcheck.

$\Xfallback = \token{\$jam\_fallback\_seal}$  
*Bandersnatch* Fallback block seal. See equation eq:ticketconditionfalse.

$\Xguarantee = \token{\$jam\_guarantee}$  
*Ed25519* Guarantee statements. See equation eq:guarantorsig.

$\Xannounce = \token{\$jam\_announce}$  
*Ed25519* Audit announcement statements. See equation eq:announcement.

$\Xticket = \token{\$jam\_ticket\_seal}$  
*Bandersnatch RingVRF* Ticket generation and regular block seal. See equation eq:ticketconditiontrue.

$\Xaudit = \token{\$jam\_audit}$  
*Bandersnatch* Audit selection entropy. See equations eq:initialaudit and eq:latertranches.

$\Xvalid = \token{\$jam\_valid}$  
*Ed25519* Judgments for valid work-reports. See equation eq:judgments.

$\Xinvalid = \token{\$jam\_invalid}$  
*Ed25519* Judgments for invalid work-reports. See equation eq:judgments.

[^1]: The gas mechanism did restrict what programs can execute on it by placing an upper bound on the number of steps which may be executed, but some restriction to avoid infinite-computation must surely be introduced in a permissionless setting.

[^2]: Practical matters do limit the level of real decentralization. Validator software expressly provides functionality to allow a single instance to be configured with multiple key sets, systematically facilitating a much lower level of actual decentralization than the apparent number of actors, both in terms of individual operators and hardware. Using data collated by on Ethereum 2, one can see one major node operator, Lido, has steadily accounted for almost one-third of the almost one million crypto-economic participants.

[^3]: Ethereum’s developers hope to change this to something more secure, but no timeline is fixed.

[^4]: Some initial thoughts on the matter resulted in a proposal by to utilize Polkadot technology as a means of helping create a modicum of compatibility between roll-up ecosystems!

[^5]: In all likelihood actually substantially more as this was using low-tier “spare” hardware in consumer units, and our recompiler was unoptimized.

[^6]: Earlier node versions utilized Arweave network, a decentralized data store, but this was found to be unreliable for the data throughput which Solana required.

[^7]: Practically speaking, blockchains sometimes make assumptions of some fraction of participants whose behavior is simply *honest*, and not provably incorrect nor otherwise economically disincentivized. While the assumption may be reasonable, it must nevertheless be stated apart from the rules of state-transition.

[^8]: 1,735,732,800 seconds after the Unix Epoch.

[^9]: This is three fewer than RISC-V’s 16, however the amount that program code output by compilers uses is 13 since two are reserved for operating system use and the third is fixed as zero

[^10]: Technically there is some small assumption of state, namely that some modestly recent instance of each service’s preimages. The specifics of this are discussed in section 14.3.

[^11]: This requirement may seem somewhat arbitrary, but these happen to be the decision thresholds for our three possible actions and are acceptable since the security assumptions include the requirement that at least two-thirds-plus-one validators are live ( discusses the security implications in depth).

[^12]: This is a “soft” implication since there is no consequence on-chain if dishonestly reported. For more information on this implication see section 16.

[^13]: The latest “proto-danksharding” changes allow it to accept 87.3KB/s in committed-to data though this is not directly available within state, so we exclude it from this illustration, though including it with the input data would change the results little.

[^14]: This is detailed at <a href="{https://hackmd.io/@XXX9CM1uSSCWVNFRYaSB5g/HJarTUhJA}" class="uri">{https://hackmd.io/@XXX9CM1uSSCWVNFRYaSB5g/HJarTUhJA}</a> and intended to be updated as we get more information.

[^15]: It is conservative since we don’t take into account that the source code was originally compiled into EVM code and thus the PVM machine code will replicate architectural artifacts and thus is very likely to be pessimistic. As an example, all arithmetic operations in EVM are 256-bit and 64-bit native PVM is being forced to honor this even if the source code only actually required 64-bit values.

[^16]: We speculate that the substantial range could possibly be caused in part by the major architectural differences between the EVM ISA and typical modern hardware.

[^17]: As an example, our odd-product benchmark, a very much pure-compute arithmetic task, execution takes 58s on EVM, and 1.04s within our PVM prototype, including all preprocessing.

[^18]: The popular code generation backend LLVM requires and assumes in its code generation that dynamically computed jump destinations always have a certain memory alignment. Since at present we depend on this for our tooling, we must acquiesce to its assumptions.

[^19]: Note that since specific values may belong to both sets which would need a discriminator and those that would not then we are sadly unable to introduce a function capable of serializing corresponding to the *term*’s limitation. A more sophisticated formalism than basic set-theory would be needed, capable of taking into account not simply the value but the term from which or to which it belongs in order to do this succinctly.

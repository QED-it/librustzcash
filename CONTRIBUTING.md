# Contributing to `librustzcash` Crates

First off, thanks for taking the time to contribute! ❤️

All types of contributions are encouraged and valued. See the [Table of
Contents](#table-of-contents) for different ways to help and details about how
this project handles them. Please make sure to read the relevant section before
making your contribution. It will make it a lot easier for us maintainers and
smooth out the experience for all involved. The community looks forward to your
contributions. 🎉

> And if you like the project, but just don't have time to contribute, that's fine. There are other easy ways to support the project and show your appreciation, which we would also be very happy about:
> - Star the project on GitHub.
> - Post about the project.
> - Refer this project in your project's readme.
> - Mention the project at local meetups and tell your friends/colleagues.


## Table of Contents

- [Code of Conduct](#code-of-conduct)
- [I Have a Question](#i-have-a-question)
- [I Want To Contribute](#i-want-to-contribute)
- [Reporting Bugs](#reporting-bugs)
- [Suggesting Enhancements](#suggesting-enhancements)
- [Styleguides](#styleguides)
- [Git Usage](#git-usage)
- [Coding Style](#coding-style)

## Code of Conduct

This project and everyone participating in it is governed by the
[Code of Conduct](https://github.com/zcash/zcash/blob/master/code_of_conduct.md). By
participating, you are expected to uphold this code. Please report unacceptable
behavior as documented in the code of conduct.


## I Have a Question

> If you want to ask a question, we assume that you have read the available documentation for the crate or crates in question. Documentation for all of the crates in this workspace is published to [docs.rs](https://docs.rs).

Before you ask a question, it is best to search for existing [Issues](/issues)
that might help you. In case you have found a suitable issue and still need
clarification, you can write your question in this issue. It is also advisable
to search the internet for answers first.

If you then still feel the need to ask a question and need clarification, we
recommend the following:

- Ask for help in the `#libraries` channel of the [Zcash R&D Discord](https://discordapp.com/channels/809218587167293450/876655911790321684).
  There are no bad questions, only insufficiently documented answers. If you're
  able to find an answer and it wasn't already in the docs, consider opening a
  pull request to add it to the documentation!
- You can also open an [Issue](/issues/new). If you do so:
  - Provide as much context as you can about what you're running into.
  - Provide project and platform versions depending on what seems relevant.

We will then attempt to triage the issue as soon as practical. Please be aware
that the maintainers of `librustzcash` have a relatively heavy workload, so
this may take some time.


## I Want To Contribute

> ### Legal Notice
> When contributing to this project, you must agree that you have authored 100% of the content, that you have the necessary rights to the content and that the content you contribute may be provided under the project licenses.

### Project Structure

`librustzcash` is a Rust workspace containing numerous interdependent crates
with a somewhat complex internal dependency relationship. Please refer to the
[README](blob/main/README.md) for a graphical view of these dependencies and
summary documentation for each module.

### Project Versioning

The libraries supplied by this project follow [Semantic
Versioning](https://semver.org/). If possible, it is desirable for users to
depend upon the latest released version. Detailed change logs are available in
the `CHANGELOG.md` file for each module.

Please note that the libraries in this workspace are under continuous
development and new SemVer major-version releases are frequent. Users of these
libraries, and in particular implementers of traits defined in them, should
expect a corresponding maintenance burden. The `CHANGELOG.md` files are vital
to understanding these changes. Under normal circumstances, proposed changes
will be considered for application against the last two major release versions;
SemVer-compatible bug fixes may be backported to versions that we are aware of
being widely in use in the Zcash ecosystem.

### Reporting Bugs

#### Before Submitting a Bug Report

A good bug report shouldn't leave others needing to chase you up for more
information. Therefore, we ask you to investigate carefully, collect
information and describe the issue in detail in your report. Please complete
the following steps in advance to help us fix any potential bug as fast as
possible.

- Determine if your bug is really a bug and not an error on your side e.g.
  using incompatible environment components/versions or violating the
  documented preconditions for an operation.
- To see if other users have experienced (and potentially already solved) the
  same issue you are having, check if there is not already a bug report
  existing for your bug or error in the [bug tracker](issues?q=label%3Abug).
- Also make sure to search the internet to see if users outside of the GitHub
  community have discussed the issue. You can also ask about your problem in
  the [Zcash R&D Discord](https://discordapp.com/channels/809218587167293450/876655911790321684).
- Collect information about the problem:
  - OS, Platform and Version (Windows, Linux, macOS, x86, ARM)
  - Version of the compiler, runtime environment, etc. depending on what seems
    relevant.
  - Your inputs and the resulting output, if revealing these values does not
    impact your privacy.
  - Can you reliably reproduce the issue? And can you also reproduce it with
    older versions?


#### How Do I Submit a Good Bug Report?

> You must never report security related issues, vulnerabilities or bugs including sensitive information to the issue tracker, or elsewhere in public. Issues that have impliciations for personal or network security should be reported as described at [https://z.cash/support/security/](https://z.cash/support/security/).


We use GitHub issues to track bugs and errors. If you run into an issue with
the project:

- Open an [Issue](/issues/new). (Since we can't be sure at this point whether
  the issue describes a bug or not, we ask you not to label the issue.)
- Explain the behavior you would expect and the actual behavior.
- Please provide as much context as possible and describe the **reproduction
  steps** that someone else can follow to recreate the issue on their own. This
  usually includes your code. For good bug reports you should isolate the
  problem and create a reduced test case.
- Provide the information you collected in the previous section.

Once it's filed:

- The project team will label the issue accordingly.
- Unless the issue is naturally hard to reproduce, such as a deadlock,
  a team member will try to reproduce the issue with your provided steps. If
  there are no reproduction steps or no obvious way to reproduce the issue, the
  team will ask you for those steps and mark the issue as `needs-repro`. Bugs
  with the `needs-repro` tag will not be addressed until they are reproduced.
- If the team is able to reproduce the issue, it will be assigned an
  appropriate category and fixed according to the criticality of the issue. If
  you're able to contribute a proposed fix, this will likely speed up the
  process, although be aware that `librustzcash` is a complex project and fixes
  will be considered in the context of safety and potential for unintentional
  misuse of overall API; you should be prepared to alter your approach based on
  suggestions from the team and for your contributions to undergo multiple
  rounds of review.


### Suggesting Enhancements

This section guides you through submitting an enhancement suggestion,
**including completely new features and minor improvements to existing
functionality**. Following these guidelines will help maintainers and the
community to understand your suggestion and find related suggestions.


#### Before Submitting an Enhancement

- Make sure that you are using the latest version, or that the enhancement you
  are proposing is suitable for implementation in the version that you rely
  upon: this requires that the feature can be implemented without a SemVer
  breaking change.
- Read the documentation of the appropriate module carefully and find out if
  the functionality is already covered, maybe by an individual configuration.
- Perform a [search](/issues) to see if the enhancement has already been
  suggested. If it has, add a comment to the existing issue instead of opening
  a new one.
- Find out whether your idea fits with the scope and aims of the project. It's
  up to you to make a strong case to convince the project's developers of the
  merits of this feature. Keep in mind that we want features that will be
  useful to the majority of our users and not just a small subset. If you're
  just targeting a minority of users, consider writing an add-on/plugin
  library.
- Note that, due to the practice of "airdrop farming", this project DOES NOT
  accept trivial PRs (spelling corrections, link fixes, minor style
  modifications, etc.) from unknown contributors. We appreciate problems of
  this sort being reported as issues, though.


#### How Do I Submit a Good Enhancement Suggestion?

Enhancement suggestions are tracked as [GitHub issues](/issues).

- Use a **clear and descriptive title** for the issue to identify the
  suggestion. The relevant module, if known, should be indicated by prefixing
  the title with `<module-name>:`.
- Provide a **step-by-step description of the suggested enhancement** in as
  many details as possible.
- **Describe the current behavior** and **explain which behavior you expected
  to see instead** and why. At this point you can also tell which alternatives
  do not work for you.
- **Explain why this enhancement would be useful** to most users. You may also
  want to point out the other projects that solved the problem and which could
  serve as inspiration.


## Styleguides

### Git Usage

This project uses a merge-based workflow. When creating a branch, it is
advisable to branch from a release tag for the crate to which the modification
will be applied. There are two cases to consider here:

- If the modification involves a SemVer-breaking API change, branch from
  the latest release tag for the crate in question.

- If the modification can be applied as a SemVer-compatible change without
  generating substantial source-code-level or semantic conflicts with the
  current state of the `main` branch, it is often useful to branch from the
  most recent tag in the series from the *previous* SemVer major release
  relative to the current state of `main`. By including the change in two
  SemVer major release versions, it can help support more users. While this
  does not ensure that a SemVer point release containing the change will be
  made, it at least makes such a release possible and helps to clarify the
  scope of the change for reviewers. Please indicate the relevant tag in the
  top message of the pull request on GitHub; the maintainers may request that
  you change the "base" branch of your PR to simplify such releases.

#### Branch History

- Commits should represent discrete semantic changes.
- When a commit alters the public API, fixes a bug, or changes the underlying
  semantics of existing code, the commit MUST also modify the affected
  submodules' `CHANGELOG.md` files to clearly document the change.
- Updated or added members of the public API MUST include complete `rustdoc`
  documentation comments.
- It is acceptable and desirable to open pull requests in "Draft" status. Only
  once the pull request has passed CI checks should it be transitioned to
  "Ready For Review".
- There MUST NOT be "work in progress" commits as part of your history, with
  the following exceptions:
  - When making a change to a public API or a core semantic change, it is
    acceptable to make the essential change as a distinct commit, without the
    associated alterations that propagate the semantic change throughout the
    rest of the codebase. In such cases the commit message must CLEARLY DOCUMENT
    the partial nature of the work, and whether the commit is expected compile
    and/or for tests to pass, and what work remains to be done to complete the
    change.
  - If a pull request is fixing a bug, the bug SHOULD be demonstrated by the
    addition of a failing unit test in a distinct commit that precedes the
    commit(s) that fix the bug. Due to the complexity of creating some tests,
    additions or other changes to the test framework may be required. Please
    consult with the maintainers if substantial changes of this sort are
    needed, or if you are having difficulties reproducing the bug in a test.

#### Commit Messages

- Commit messages should have a short (preferably less than ~120 characters) title.
- The body of each commit message should include the motivation for the change,
  although for some simple cases (such as the application of suggested changes) this
  may be elided.
- When a commit has multiple authors, please add `Co-Authored-By:` metadata to
  the commit message to include everyone who is responsible for the contents of
  the commit; this is important for determining who has the most complete
  understanding of the changes.

#### Pull Request Review

- It is acceptable and desirable to use a rebase-based workflow within the
  context of a single pull request in order to produce a clean commit history.
  Two important points:
  - When changes are requested in pull request review, it is desirable to apply
    those changes to the affected commit in order to avoid excessive noise in the
    commit history. The [git revise](https://github.com/mystor/git-revise) plugin
    is **extremely** useful for this purpose.
  - If a maintainer or other user uses the GitHub `suggestion` feature to
    suggest explicit code changes, it's usually best to accept those changes
    via the "Apply Suggested Changes" GitHub workflow, and then to amend the
    resulting commit to fix any related compilation or test errors or
    formatting/lint-related changes; this ensures that correct co-author
    metadata is included in the commit. If the changes are substantial enough
    that it makes more sense to rewrite the original commit, make sure to
    include co-author metadata in the commit message when doing so (squashing
    the GitHub-generate suggestion acceptance commit(s) together with the
    original commit in an interactive rebase can make this easy).

### Coding Style

The `librustzcash` authors hold our software to a high standard of quality. The
list of style requirements below is not comprehensive, but violation of any of
the following guidelines is likely to cause your pull request to be rejected or
changes to be required.

#### Type Safety

In `librustzcash` code, type safety is of paramount importance. This has
numerous implications, including but not limited to the following:
- Invalid states should be made unrepresentable at the type level. In general:
  - `structs` should have all internal members private or crate-private, and
    should expose constructors that result in `Result<...>` or `Option<...>`
    that check for invariant violations, if any such violations are possible.
    Provide public or crate-public accessors for internal members when necessary.
  - "bare" native integer types, strings, and so forth should be avoided in
    public APIs; use "newtype" wrappers with clearly documented semantics instead.
  - Avoid platform-specific integer sizing (i.e. `usize`) except when e.g.
    indexing into a Rust collection type that already requires such semantics.
  - Use `enum`s liberally; a common type safety failure in many other languages
    is that product (struct or tuple) types containing potentially invalid
    state space are used.
  - Use custom `enum`s with semantically relevant variants instead of boolean
    arguments and return values.
- Prefer immutability; make data types immutable unless there is a strong
  reason to believe that values will need to be modified in-place for
  performance reasons.
- Take care when introducing and/or using structured enum variants, because
  Rust does not provide adequate language features for making such values
  immutable or ensuring safe construction. Instead of creating structured or
  tuple variants, it is often preferable for a variant to wrap an immutable
  type and expose a safe constructor for the variant along with accessors for
  the members of the wrapped type.

#### Side Effects & Capability-Oriented Programming

Whenever it's possible to do without impairing performance in hot code paths,
prefer a functional programming style, with allowances for Rust's limitations.
This means:
- Write referentially transparent functions. A referentially transparent
  function is one that, given a particular input, always returns the same
  output.
- Avoid mutation whenever possible. If it's strictly necessary, use mutable
  variables only in the narrowest possible scope.
- In Rust, we don't have good tools for referentially transparent treatment
  of operations that involve side effects. If a statement produces or makes use
  of a side-effect, the context in which that statement is executed should use
  imperative programming style to make the presence of the side effect more
  evident. For example, use a `for` loop instead of the `map` function of a
  collection if any side effect is performed by the body of the loop.
- If a procedure or method will invoke operations that produce side effects,
  the capability to perform such side effects should be provided to the
  procedure as an explicit argument. For example, if a procedure needs to
  access the current time, that procedure should take an argument `clock: impl
  Clock` where `Clock` is a trait that provides a method that allows the caller
  to obtain the current time. 
- Effect capabilities should be defined independent of implementation concerns;
  for example, a data persistence capability should be defined to operate on
  high-level types appropriate to the domain, not to a particular persistence
  layer or serialization.

## Attribution
This guide is based on the template supplied by the
[CONTRIBUTING.md](https://contributing.md/) project.


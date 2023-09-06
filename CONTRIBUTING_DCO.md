# Contributing to syscall-failure-analyzer

We welcome contributions from the community and first want to thank you for taking the time to contribute!

Please familiarize yourself with the [Code of Conduct](https://github.com/vmware/.github/blob/main/CODE_OF_CONDUCT.md) before contributing.

Before you start working with syscall-failure-analyzer, please read our [Developer Certificate of Origin](https://cla.vmware.com/dco). All contributions to this repository must be signed as described on that page. Your signature certifies that you wrote the patch or have the right to pass it on as an open-source patch.

## Ways to contribute

We welcome many different types of contributions and not all of them need a Pull request. Contributions may include:

* New features and proposals
* Documentation
* Bug fixes
* Issue Triage
* Answering questions and giving feedback
* Helping to onboard new contributors
* Other related activities

## Getting started

This section provides a comprehensive guide on how to contribute to the project by setting up your development environment, and ensuring code quality before submitting a pull request. Though the project is in Python, which simplifies the build process, it's crucial to follow these guidelines for a smooth collaboration.

### Development Environment Setup

1. **Clone the Repository:** Clone the repository to your local machine using the following command in your terminal:

    ```bash
    git clone https://github.com/vmware-labs/syscall-failure-analyzer
    ```

2. **Navigate to the Project Directory:**

    ```bash
    cd your-repository
    ```

3. **Install Required Packages:** Use `pip` to install the required Python packages:

    ```bash
    pip install -r requirements.txt
    ```

### Ensuring Code Quality

Before submitting a pull request, make sure that your code adheres to the following guidelines:

- **No MyPy Warnings:** Your code should not produce any MyPy warnings. Run the following command to check:

    ```bash
    mypy .
    ```

    If you see any warnings, correct the type annotations to resolve them before submitting your pull request.

### Submitting a Pull Request

1. **Create a New Branch:**

    ```bash
    git checkout -b your-feature-branch
    ```

2. **Add and Commit Your Changes:**

    ```bash
    git add .
    git commit --signoff -m "Your commit message"
    ```

3. **Push the Changes:**

    ```bash
    git push origin your-feature-branch
    ```

4. Navigate to the original repository and create a new pull request. Compare the original `main` or `master` branch with your `your-feature-branch`.

5. After submitting the pull request, maintainers will review your changes. Upon approval, your code will be merged into the main codebase.

### Common Issues

Currently, there are no common issues to be aware of. As the project evolves, this section will be updated accordingly.

### Testing

As of now, the project does not have automated tests. Please disregard this section until tests are added to the repository.

## Contribution Flow

This is a rough outline of what a contributor's workflow looks like:

* Make a fork of the repository within your GitHub account
* Create a topic branch in your fork from where you want to base your work
* Make commits of logical units
* Make sure your commit messages are with the proper format, quality and descriptiveness (see below)
* Push your changes to the topic branch in your fork
* Create a pull request containing that commit

We follow the GitHub workflow and you can find more details on the [GitHub flow documentation](https://docs.github.com/en/get-started/quickstart/github-flow).

### Pull Request Checklist

Before submitting your pull request, we advise you to use the following:

1. Check if your code changes will pass both code linting checks and unit tests.
2. Ensure your commit messages are descriptive. We follow the conventions on [How to Write a Git Commit Message](http://chris.beams.io/posts/git-commit/). Be sure to include any related GitHub issue references in the commit message. See [GFM syntax](https://guides.github.com/features/mastering-markdown/#GitHub-flavored-markdown) for referencing issues and commits.
3. Check the commits and commits messages and ensure they are free from typos.

## Reporting Bugs and Creating Issues

For specifics on what to include in your report, please follow the guidelines in the issue and pull request templates when available.


## Ask for Help

The best way to reach us with a question when contributing is to ask on:

* The original GitHub issue


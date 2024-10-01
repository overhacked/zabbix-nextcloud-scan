# Contributing

## Local Development
### Setting up an environment
This project uses [Poetry](https://python-poetry.org/) to manage development dependencies
and [pre-commit](https://pre-commit.com/) to enforce code style and lints.

1. First, [have Poetry installed](https://python-poetry.org/docs/#installation).

   Alternatively, you can install `pre-commit` directly using `pip`:
   ```
   pip install pre-commit
   ```
   *If you do this, skip to step 3 and omit `poetry run` from the command.*

2. To create a virtual environment and install dev dependencies, run:
   ```
   poetry install --with=dev
   ```

3. Install the `pre-commit` git hook scripts to your local repository:
   ```
   poetry run pre-commit install
   ```

Now, work on your commit, and Git will run the pre-commit hooks before you are able to
commit changes. The pre-commit hooks also run as CI checks on pull requests.

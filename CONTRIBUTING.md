# Contributing to CONIKS Go

We'd love for you to contribute to our source code! Here are the guidelines
we'd like you to follow:

 - [Found an Issue?](#issue)
   - [Submission Prerequisites](#prereq)
   - [Submission Guidelines](#submit)
 - [Coding Rules](#rules)

## <a name="issue"></a> Found an Issue?
If you find a bug in the source code, you can help us by submitting an
issue to our [GitHub Repository][github]. Even better, you can submit a
Pull Request with a fix.

### <a name="prereq"></a> Submission Prerequisites
Run the following commands to install the prerequisites needed to
complete your pull request submission:

Download dependencies: `dep ensure`  (How to use `dep`: https://github.com/golang/dep).

### <a name="submit"></a> Submission Guidelines
Before you submit your pull request consider the following guidelines:

* Search [GitHub](https://github.com/coniks-sys/coniks-go/pulls)
for an open or closed Pull Request that relates to your submission.
You don't
want to duplicate effort.
* Create separate pull requests for separate bug fixes/features.
* Make your changes in a new git branch.
* Create your patch, **including appropriate test cases**.
* Follow our [Coding Rules](#rules).
* Run `go fmt` and `go vet` to correct any styling errors in the code.
* Run `go test` to run the full test suite.
* Run `dep ensure` to update the dependencies.
* Push your branch to GitHub.
* In GitHub, send a pull request to `:master`. Please include a detailed description of your changes, and if/how they affect the rest of the CONIKS system.
* If we suggest changes then
  * Make the required updates.
  * Re-run the test suite and build to ensure the code is still healthy.
  * Rebase your branch and force push to your GitHub repository (this will update your Pull Request)

That's it! Thank you for your contribution!

#### After your pull request is merged

After your pull request is merged, you can safely delete your branch and pull the changes
from the main (upstream) repository.

## <a name="rules"></a> Coding Rules
To ensure consistency throughout the source code, keep these rules in mind as you are working:

* All features or bug fixes **must be tested**.
* All public API methods **must be documented**.


[github]: https://github.com/coniks-sys/coniks-go
[issues]: https://github.com/coniks-sys/coniks-go/issues

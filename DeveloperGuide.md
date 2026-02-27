## Developers Guide

### Setting up the project to run in maven locally to develop
To work with the project locally and run it with a Jenkins server, follow these steps:

Make sure to have Java 21 installed. Maven is optional because this repo includes the Maven Wrapper (recommended).

```
# content of maven.sh file
export JAVA_HOME=/usr/lib/jvm/java-21-openjdk-amd64
#export PATH=$JAVA_HOME/bin:$PATH
export M2_HOME=/opt/maven
export MAVEN_HOME=/opt/maven
export PATH=${M2_HOME}/bin:${PATH}
```

#### Using the Maven Wrapper (recommended)
Parent 5.9 requires Maven >= 3.9.6. The wrapper in this repo is pinned to a compatible Maven (3.9.9), so you don’t need a system Maven.

- Linux/macOS:
```
./mvnw -U clean verify
```
- Windows (PowerShell/CMD):
```
./mvnw.cmd -U clean verify
```

You can use the wrapper for all build and run commands below.

1. Run Jenkins server locally with the plugin being deployed:
```
# Recommended (uses the Maven Wrapper)
./mvnw hpi:run -Dport=5025

# Alternatively, with system Maven (ensure Maven >= 3.9.6)
# source /etc/profile.d/maven.sh
# mvn hpi:run -Dport=5025
```
> Enter https://localhost:5025/jenkins in your browser

**Note:** Make sure that **port 5025** is free on your machine.

### Setting up dev-test environment in docker

* Make sure a `temp-jenkins` directory exists in your home directory.

* Build the project:
```
./mvnw clean install
```

* Generate the `hpi` file:
```
./mvnw hpi:hpi
```

The generated `hpi` file can be found in the `target` folder of your project directory.


* Spin up the jenkins instance with the following command:

**Note:** Make sure that **port 8082** is free on your machine.

```
docker-compose up
```
or if you prefer detach mode
```
docker-compose up -d
```

3. Install the plugin `hpi` file in your Jenkins instance:
>- Go to your Jenkins instance. Enter https://localhost:8082/jenkins in your browser
>- Navigate to **Manage Jenkins** > **Manage Plugins** > **Advanced Settings**.
>- In the **Deploy Plugin** section, click **Choose File**.
>- Select the generated `hpi` file and click **Deploy**.
>- **Restart** your Jenkins instance.

**Note:** `xcode-select` may need to be installed in **Mac** if any kind of error like - `git init` failed or developer path related error is faced while running job from jenkins instance.

Command to install `xcode-select` in Mac:
```
xcode-select --install
```

### Publishing a new release to the Jenkins Update Center

This plugin is published from the [jenkinsci/finite-state-analysis-plugin](https://github.com/jenkinsci/finite-state-analysis-plugin) fork, which is the official Jenkins community repository. The upstream development happens in [FiniteStateInc/finite-state-jenkins-plugin](https://github.com/FiniteStateInc/finite-state-jenkins-plugin).

#### Repository relationship

| Repository | Purpose |
|---|---|
| `FiniteStateInc/finite-state-jenkins-plugin` | Upstream — where development happens |
| `jenkinsci/finite-state-analysis-plugin` | Fork — where releases are published from |

#### How versioning works

Versions are computed automatically by the `git-changelist-maven-extension` (configured in `.mvn/extensions.xml`). There is no manual version bumping — the version is derived from the commit history.

#### Step-by-step release process

1. **Push your changes to the upstream repo** (`FiniteStateInc/finite-state-jenkins-plugin`) via a pull request as usual.

2. **Sync the fork with upstream** by opening a PR from the upstream into the fork:
   - Go to: https://github.com/jenkinsci/finite-state-analysis-plugin/compare/main...FiniteStateInc:finite-state-jenkins-plugin:main
   - Set **base** to `jenkinsci/finite-state-analysis-plugin` → `main`
   - Set **head** to `FiniteStateInc/finite-state-jenkins-plugin` → `main`
   - Give the PR a descriptive title (e.g., "Sync fork with upstream")
   - Click **Create pull request**

3. **Merge the PR** on the `jenkinsci` repo:
   - Verify the green "Able to merge" checkmark
   - Click **Merge pull request** → **Confirm merge**
   - Wait for all CI checks to pass (Jenkins runs tests on Linux JDK 21 + Windows JDK 17)

4. **Trigger the release** by running the CD workflow manually:
   - Go to [Actions → cd](https://github.com/jenkinsci/finite-state-analysis-plugin/actions/workflows/cd.yaml)
   - Click **Run workflow**
   - Leave `validate_only` **unchecked** (false) to publish a real release
   - Click **Run workflow**

5. **Verify the release**:
   - Check the [Releases page](https://github.com/jenkinsci/finite-state-analysis-plugin/releases) for the new version
   - The plugin will be available on the [Jenkins Update Center](https://plugins.jenkins.io/finite-state-analysis/) shortly after

#### Dry-run (validate only)

To preview release notes without actually publishing, run the CD workflow with `validate_only` checked (true). This drafts a "next" release without publishing it.

#### Troubleshooting

- If the CD workflow does not trigger automatically after merging, run it manually as described in step 4.
- Check the [Actions tab](https://github.com/jenkinsci/finite-state-analysis-plugin/actions) for build logs if something fails.
- The `MAVEN_USERNAME` and `MAVEN_TOKEN` secrets must be configured in the `jenkinsci` repo settings for publishing to work.

### Managing developer access and code reviews

#### CODEOWNERS

The file `.github/CODEOWNERS` in the `jenkinsci` fork controls who gets automatically requested for review on every PR:

```
* @jenkinsci/finite-state-analysis-plugin-developers
```

This means all PRs require an approving review from a member of the `finite-state-analysis-plugin-developers` team before they can be merged.

**Limitation:** CODEOWNERS only supports teams and users within the `jenkinsci` organization. You cannot reference teams from other organizations (e.g., `@FiniteStateInc/...`).

#### Adding new developers

New developers need to be members of the `jenkinsci` GitHub organization and the `finite-state-analysis-plugin-developers` team in order to review and merge PRs.

Since `jenkinsci` is managed by the Jenkins infrastructure team, you cannot directly invite people. Instead, use the **Repository Permissions Updater**:

1. Go to [jenkins-infra/repository-permissions-updater](https://github.com/jenkins-infra/repository-permissions-updater)
2. Find or create the file `permissions/plugin-finite-state-analysis.yml`
3. Submit a PR adding the new developer's GitHub username:

```yaml
---
name: "finite-state-analysis"
github: "jenkinsci/finite-state-analysis-plugin"
developers:
  - "cpfarherFinitestate"
  - "newDeveloperGitHubUsername"
```

4. Once a Jenkins admin merges the PR, the user is invited to the `jenkinsci` org and added to the plugin's developer team automatically.

Alternatively, you can post a request at [community.jenkins.io](https://community.jenkins.io) in the **Hosting** category with the plugin name and the GitHub username to add.
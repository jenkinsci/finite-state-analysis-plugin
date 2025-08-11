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
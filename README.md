# Dependency Checker

The dependency checker can find dependent software packages in your project using dependency management tools (e.g. Maven, Gradle, NPM, etc) and identify vulnerable software packages using our vulnerability database. The dependency checker currently supports Maven, Gradle, NPM, Yarn, and Bower based projects and requires an access to a vulnerability database.

## Getting Started

### Prerequisite

#### Set up a vulnerability database
You can set up your own vulnerability database using a sample data set and instructions that we provided here:
https://github.com/canvasslabs/canvass_for_security-sample_vuln_db

#### Set up an environment for dependency checker

Dependency checker runs only on *nix system. It has been tested on Ubuntu 16.04 and 18.04 operating systems.
The followings must be installed on your *nix system.
* Python 3 (Tested on version 3.5.2)
* Java 1.8 (Tested on version 1.8)
* Maven 3 (Tested on version 3.3.9)
* Gradle 5 (Tested on 5.2.1)
* NPM 6 (Tested on 6.4.1)
* Yarn (Tested on 1.12.3)
* Bower (Tested on 1.8.8)



Steps to set up a virtual environment and install requirements
```
git clone https://github.com/canvasslabs/dependency_checker.git
cd dependecy_checker
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```


Steps to set vulnerability database login credentials to your system environment

On *nix system
```
export CL_USERNAME="<Your username>"
export CL_PASSWORD="<Your password>"
```


## How to run

1) Change directory to where dependency_checker.py module is located.
```
cd dependency_checker/vuln_search
```
2) Run the command below
```
python3 dependency_checker.py <Path to a project to scan> --outputFile <Path to an output report>
```



## Test run

You can do a test run using our demo project.

First, clone the demo project
```
git clone https://github.com/canvasslabs/npm_demo.git
```

Change directory to where dependency checker.py module is located and run the command below.
A report file will be generated at dependency_checker/vuln_search/npm_demo_report.txt
```
cd dependency_checker/vuln_search
python3 dependency_checker.py <Path to the demo project> --outputFile npm_demo_report.txt
```



## License

This project is licensed under the Apache 2.0 License - see the LICENSE.txt file for details

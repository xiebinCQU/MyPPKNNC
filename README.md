# MyPPKNNC
<p>Official Java implementation of "Access Oblivious and Privacy-Preserving K Nearest Neighbors Classification in Dual Clouds". The implementation is based on JDK 9 and windows 10 operating system.</p>

# Quick Start
## Cloning
>git clone https://github.com/xiebinCQU/MyPPKNNC
>
>cd MyPPKNNC

## Run simulation
<p>Here, to simplify the executing process, the provided privacy-preserving KNN classification demo will be ran based on a simulated environment in one desktop. For ease of understanding, we first introduce some important components and then provide an example to show how to start up the demo.</p>

### Components

* MyPPKNNC/MyPPKNN/src/data/

>This package contains three synthetic datasets (testTrain10.csv, testTrain20.csv, testTrain30.csv) and a preprocessed real-world dataset (handled_crowdsourcing.csv, handledcrowdsourcing_test.csv). Besides, it also contains a configuration file (config.properties) where the reader can modify the content to change the used dataset and other parameters in KNN during the experiment.

* MyPPKNNC/MyPPKNN/src/com/xiebin/algorithm/

> This package contains a implementation of the Elgamal variant.

* MyPPKNNC/MyPPKNN/src/com/xiebin/entity/

> This package contains several Java classes which serve as entities to store ciphertext, data records and other information.

* MyPPKNNC/MyPPKNN/src/com/xiebin/utils/

> This package contains several useful tools, such as DatasetGenerator.java (generate synthetic datasets), ParameterGenerator.java(generate the public and secret key of Elgamal variant), CommunicationAccumulator.java (record communication traffic) and so on.

* MyPPKNNC/MyPPKNN/src/com/xiebin/simulate/

> This package contains a jave source file to simulate the proposed scheme in a desktop, which contains several methods to simulate different stages of our scheme.

### Start up the demo

<p>The PPKNN demo can be tested by:</p>

> Java Test

<p>The reader can test different KNN parameters and datasets by modifying the content in config.properties.</p>

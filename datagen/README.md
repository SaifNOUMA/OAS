# Data Generation

This folder contains a simple program to generate random data. It stores locally, and we consider it as our log dataset.

## Build

```c
    g++ data_gen.cpp -lssl -lcrypto -o data_gen
```

## Execution

```c
./data_gen SIZE_LOGS_GB
```

Where SIZE_LOGS_GB denotes the size of the log entries' set in GB.


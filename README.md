# Knocker

Knocker is a fast port scanner script written in Python that uses threading for quick port scanning and integrates Nmap for detailed service information.

## Features

- Scans a range of ports on a target IP address using multiple threads for speed.
- Optionally performs a detailed scan using Nmap to get service information for open ports.
- Customizable number of threads and port range.

## Usage

### Installation

1. Clone the repository:
    ```bash
    git clone https://github.com/therealslimshady0/Knocker.git
    cd knocker
    ```

2. Install the required Python packages:
    ```bash
    pip install -r requirements.txt
    ```

   Alternatively, you can install the dependencies directly:
    ```bash
    pip install argparse python-nmap tabulate
    ```

3. Ensure Nmap is installed on your system. You can download it from [https://nmap.org/download.html](https://nmap.org/download.html).

### Running the Scanner

To run the port scanner, use the following command format:

```bash
python scanner.py <target_ip> [options]
# Knocker
# Knocker

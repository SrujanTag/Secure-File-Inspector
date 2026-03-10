# Secure File Inspector

A simple Java program that checks files in a folder for sensitive information and dangerous code. 

## What it does

* **Scan Folders:** Reads all files in a given folder to look for hidden risks.
* **Finds Personal Data (PII):** Spots emails, IP addresses, and phone numbers.
* **Finds Bad Code:** Looks for dangerous commands (like `cmd.exe`, `powershell`, or `eval`).
* **Delete Bad Files:** Lets you safely delete files that are marked as "INFECTED".
* **Save Reports:** Saves your scan results into a clean `Scan_Report.csv` file.

## Tech Stack

* **Language:** Java
* **Environment:** Console/Terminal

## How to Run It

1. Make sure you have Java installed on your computer.
2. Open your terminal or command prompt.
3. Compile the code:
   ```bash
   javac Secure_File_Inspector.java

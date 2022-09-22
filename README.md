# Confluence Vulnerability Scanner
**Confluence Vulnerability Scanner** is an automated Python-based tool designed to identify security vulnerabilities in Confluence instances by checking for known CVEs (Common Vulnerabilities and Exposures).
This tool helps administrators and security professionals efficiently assess the security posture of their Confluence instances.

![CLI](https://img.shields.io/badge/CLI-Tool-green)
![Python](https://img.shields.io/badge/Python-3.6%2B-blue)
![OSINT](https://img.shields.io/badge/Confluence-Vulnerability-Scanner)


<p align="center">
  <img src="https://i.postimg.cc/ydypdVgc/Chat-GPT-Image-Sep-21-2025-08-02-50-PM.png" alt="ConfluPwn Logo" width="600">
</p>


## Key Features

* **Automated Scanning:** Automatically checks multiple known CVEs against your Confluence instance.
* **Detailed Reports:** Provides clear reports about vulnerable and non-vulnerable endpoints.
* **Easy to Use:** Simple command-line interface for quick and efficient usage.

## Installation

1. **Clone the Repository**

```bash
git clone https://github.com/odaysec/confluPwn.git
cd confluPwn
```

2. **Install Dependencies**
   Make sure you have Python 3 and `pip` installed. Then install the required dependencies:

```bash
pip3 install -r requirements.txt
```

3. **Create a Virtual Environment**
   It is recommended to use a virtual environment to isolate project dependencies:

```bash
python3 -m venv confluenv
```

4. **Activate the Virtual Environment**
   On Linux / macOS:

```bash
source confluenv/bin/activate
```

On Windows:

```bash
.\confluenv\Scripts\activate
```

5. **Usage**
   Run the following command to start scanning:

```bash
python3 conflucheck.py --url https://<your-confluence-url> --payloads payloads.json
```

Replace `<your-confluence-url>` with the target Confluence instance URL.
The tool will test various vulnerable endpoints and generate a detailed report.

## Payloads

The payloads used for vulnerability checks are stored in `payloads.json`.
Example payloads:

```json
{
  "CVE-2019-3396": "/rest/tinymce/1/macro/preview",
  "CVE-2021-26084": "/pages/createpage-entervariables.action?SpaceKey=x",
  "CVE-2022-26134": "/%24%7Bclass%3Acom.opensymphony.webwork.ServletActionContext%7D",
  "CVE-2022-26138": "/setup/setupadministrator.action",
  "CVE-2023-22515": "/server-info.action"
}
```

You can customize or extend the payloads to cover more CVEs and potential attack vectors.

## References

* [CVE-2019-3396](https://nvd.nist.gov/vuln/detail/CVE-2019-3396)
* [CVE-2021-26084](https://nvd.nist.gov/vuln/detail/CVE-2021-26084)
* [CVE-2022-26134](https://nvd.nist.gov/vuln/detail/CVE-2022-26134)
* [CVE-2022-26138](https://nvd.nist.gov/vuln/detail/CVE-2022-26138)
* [CVE-2023-22515](https://nvd.nist.gov/vuln/detail/CVE-2023-22515)



<p align="center">
  <a href="https://star-history.com/#odaysec/confluPwn&Date">
   <picture>
     <source media="(prefers-color-scheme: dark)" srcset="https://api.star-history.com/svg?repos=odaysec/confluPwn&type=Date&theme=dark" />
     <source media="(prefers-color-scheme: light)" srcset="https://api.star-history.com/svg?repos=odaysec/confluPwn&type=Date" />
     <img alt="Star History Chart" src="https://api.star-history.com/svg?repos=odaysec/confluPwn&type=Date" />
   </picture>
  </a>
</p>


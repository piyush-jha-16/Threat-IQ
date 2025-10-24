# Threat-IQ - Advanced Threat Scanner

A comprehensive, web-based threat analysis platform that provides advanced security scanning for documents, executables, URLs, and archive files. Threat-IQ helps identify potential security threats and malicious content with detailed analysis reports.

## Features

### Multi-Format Analysis
- **Document Analysis:** Scan PDF, DOCX, XLSX, PPTX files for embedded threats and malicious content  
- **Executable Analysis:** Deep analysis of EXE, DLL, MSI, and script files for suspicious behaviors  
- **URL Safety Check:** Analyze URLs for phishing, malware, and security threats  
- **Archive Scanner:** Inspect ZIP, RAR, TAR files without extraction  

### Advanced Threat Detection
- Malware hash detection  
- Suspicious URL identification and categorization  
- Behavioral analysis for executable files  
- Content pattern matching for malicious indicators  
- File structure analysis and metadata examination  

### User Experience
- Modern, responsive dark/light theme interface  
- Real-time threat scoring with visual charts  
- Detailed analysis reports with actionable insights  
- Drag-and-drop file upload functionality  
- Progress tracking for analysis operations  

## Supported File Formats

### Document Analysis
- **Formats:** PDF, DOCX, DOC, XLSX, XLS, PPTX, PPT  
- **Maximum file size:** 50MB  

### Executable Analysis
- **Formats:** EXE, DLL, MSI, BAT, CMD, PS1, VBS, SCR, COM, SYS, OCX  
- **Maximum file size:** 100MB  

### Archive Analysis
- **Formats:** ZIP, RAR, TAR, 7Z  
- **Maximum file size:** 100MB  

### Executable File Analyzer
- **Formats:** EXE, DLL
- **Maximum file size:** 100MB
- 
## Installation

### Prerequisites
- Web browser with JavaScript enabled  
- Backend API server  

### Quick Start
1. Clone the repository  
2. Serve the files using a local web server  
3. Open your browser and navigate to the local server address  

## Usage

### Document Analysis
1. Navigate to the "Document Analysis" section  
2. Upload a document file  
3. Click "Analyze Document" to start the scan  
4. Review the threat score and detailed analysis report  

### Executable Analysis
1. Go to the "Executable File Analyzer" section  
2. Upload an executable file  
3. Click "Analyze Executable" to begin analysis  
4. Examine behavioral patterns and threat indicators  

### URL Analysis
1. Access the "URL Safety Analyzer" section  
2. Enter a complete URL including protocol  
3. Click "Analyze URL" to check for threats  
4. View safety assessment and risk factors  

### Archive Analysis
1. Visit the "Archive File Analyzer" section  
2. Upload an archive file  
3. Click "Analyze Archive" to scan contents  
4. Review file structure and threat assessment  

## Threat Scoring System
| Score Range | Risk Level | Description |
|--------------|-------------|-------------|
| 0-20 | Very Low Risk | File appears safe |
| 21-40 | Low Risk | Minor concerns detected |
| 41-60 | Medium Risk | Suspicious elements found |
| 61-80 | High Risk | Significant threats identified |
| 81-100 | Very High Risk | Malicious content confirmed |

## API Integration
The application requires a backend API for full functionality. Update the API base URL in the JavaScript configuration to point to your backend service.

## Security Considerations
- All file processing happens client-side for preview  
- Actual analysis requires backend API with proper security measures  
- Implement file size limits to prevent resource exhaustion  
- Use HTTPS in production environments  
- Consider rate limiting for API endpoints  

## Contributing
1. Fork the repository  
2. Create a feature branch  
3. Commit your changes  
4. Push to the branch  
5. Submit a pull request  

## License
This project is licensed under the MIT License.

## Disclaimer
Threat-IQ is a security analysis tool designed to assist in threat detection. It should be used as part of a comprehensive security strategy and not as the sole method for determining file safety. Always exercise caution when handling potentially malicious files and consult with security professionals for critical security decisions.

## Support
For support, bug reports, or feature requests, please open an issue on the GitHub repository or contact the development team.

## Version History
**1.0.0**
- Initial release  
- Document, executable, URL, and archive analysis  
- Threat scoring and visualization  
- Responsive dark/light theme interface

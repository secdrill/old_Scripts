# I only added few logic rest of the script is from AI

import os
import re
import base64
import hashlib
import json
import html
import fitz
from email import policy
from email.parser import BytesParser
from bs4 import BeautifulSoup
from urllib.parse import unquote
from pathlib import Path
import argparse


URL_REGEX = r'https?://[^\s"<>()]+'
IP_REGEX = r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b'
DOMAIN_REGEX = r'\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+(?:[a-z]{2,})\b'
EMAIL_REGEX = r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b'
PDF_URL_REGEX = r'(?:(?:https?://|www\.)[^\s<>"\'\[\]\(\)]+|(?:[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}(?:/[^\s<>"\'\[\]\(\)]*)?))'


def get_argument():
    parser = argparse.ArgumentParser(prog='EmailExtract.py', description='This Script will extract the attachment, Url and all the metadata of eml file and will also extract the url from Attachment like pdf')
    parser.add_argument('-f', '--file', dest='eml', help='eml file')
    args = parser.parse_args()
    if not args.eml:
        parser.error("[-] Please supply the eml file. use --help for more info")    
    return args

def sanitize_foldername(name: str) -> str:
    """Replaces illegal characters in file and folder names with underscores."""
    name = re.sub(r'[<>:"/\\|?*\']', '_', name)
    return name.strip().rstrip('. ')

def save_attachment(file: Path, payload: bytes) -> None:
    """Save attachment to disk."""
    with file.open('wb') as f:
        print(f'>> Saving attachment to "{file}"')
        f.write(payload)

def extract_urls_from_pdf(pdf_path: Path) -> list:
    """Extract URLs from a PDF file (text, annotations, metadata)."""
    urls = set()
    try:
        doc = fitz.open(pdf_path)
        for page in doc:
            for link in page.get_links():
                uri = link.get("uri")
                if uri and 'safelinks.protection.outlook.com' not in uri:
                    urls.add(uri)
            text = page.get_text()
            text = ''.join(c for c in text if c.isprintable() or c.isspace())
            text_urls = re.findall(PDF_URL_REGEX, text)
            urls.update([url for url in text_urls if 'safelinks.protection.outlook.com' not in url])
        metadata = doc.metadata
        for value in metadata.values():
            if isinstance(value, str):
                value = ''.join(c for c in value if c.isprintable() or c.isspace())
                meta_urls = re.findall(PDF_URL_REGEX, value)
                urls.update([url for url in meta_urls if 'safelinks.protection.outlook.com' not in url])
        doc.close()
    except Exception as e:
        print(f'>> Error processing PDF "{pdf_path}": {str(e)}')
    return list(urls)

def extract_attachments(email_message, destination: Path) -> list:
    """Extract attachments from email and save to destination."""
    attachments_info = []
    email_subject = email_message.get('Subject') or 'no_subject'
    basepath = destination / sanitize_foldername(email_subject)
    basepath.mkdir(exist_ok=True, parents=True)

    attachments = [item for item in email_message.iter_attachments() if item.is_attachment()]
    if not attachments:
        print('>> No attachments found.')
        return attachments_info

    for attachment in attachments:
        filename = attachment.get_filename() or 'attachment'
        safe_filename = sanitize_foldername(filename)
        filepath = basepath / safe_filename
        payload = attachment.get_payload(decode=True)
        if payload:
            md5 = hashlib.md5(payload).hexdigest()
            sha256 = hashlib.sha256(payload).hexdigest()
            content_type = attachment.get_content_type()
            attachments_info.append({
                'filename': safe_filename,
                'content_type': content_type,
                'size': len(payload),
                'md5': md5,
                'sha256': sha256,
                'is_image': content_type.startswith('image/'),
                'filepath': filepath
            })
            if filepath.exists():
                print(f'>> The file "{safe_filename}" already exists! Skipping...')
            else:
                save_attachment(filepath, payload)
                if content_type == 'application/pdf':
                    pdf_urls = extract_urls_from_pdf(filepath)
                    attachments_info[-1]['pdf_urls'] = pdf_urls

    return attachments_info

def extract_eml_info(file_path):
    if not os.path.exists(file_path):
        return {"error": f"File {file_path} not found, bro. Check the path."}, []

    try:
        with open(file_path, 'rb') as f:
            msg = BytesParser(policy=policy.default).parse(f)
    except Exception as e:
        return {"error": f"Failed to parse .eml file: {str(e)}"}, []

    soc_info = {}
    urls = []

    headers = ['From', 'To', 'Subject', 'Date', 'Message-ID', 'Return-Path', 'X-Originating-IP', 'X-Mailer', 'Reply-To']
    for hdr in headers:
        soc_info[hdr] = msg[hdr] if msg[hdr] else "N/A"

    auth_headers = ['Received-SPF', 'Authentication-Results', 'DKIM-Signature', 'DMARC']
    soc_info['Auth_Results'] = {hdr: msg[hdr] if msg[hdr] else "N/A" for hdr in auth_headers}

    body_text = ""
    html_text = ""
    decoded_blobs = []

    if msg.is_multipart():
        for part in msg.walk():
            content_type = part.get_content_type()
            if content_type in ['text/plain', 'text/html']:
                try:
                    charset = part.get_content_charset() or 'utf-8'
                    content = part.get_payload(decode=True).decode(charset, errors='ignore')
                    content = html.unescape(content)
                    content = ''.join(c for c in content if c.isprintable() or c.isspace())
                    if content_type == 'text/plain':
                        body_text += content
                    elif content_type == 'text/html':
                        html_text += content
                    found_urls = re.findall(URL_REGEX, content)
                    urls += [url for url in found_urls if 'safelinks.protection.outlook.com' not in url]
                except:
                    pass
            elif 'base64' in str(part.get('Content-Transfer-Encoding', '')).lower():
                try:
                    decoded = base64.b64decode(part.get_payload(), validate=True)
                    decoded_content = decoded.decode('utf-8', errors='ignore')
                    decoded_content = ''.join(c for c in decoded_content if c.isprintable() or c.isspace())
                    decoded_blobs.append(decoded_content)
                    found_urls = re.findall(URL_REGEX, decoded_content)
                    urls += [url for url in found_urls if 'safelinks.protection.outlook.com' not in url]
                except:
                    pass
    else:
        content_type = msg.get_content_type()
        charset = msg.get_content_charset() or 'utf-8'
        try:
            content = msg.get_payload(decode=True).decode(charset, errors='ignore')
            content = html.unescape(content)
            content = ''.join(c for c in content if c.isprintable() or c.isspace())
            if content_type == 'text/plain':
                body_text = content
            elif content_type == 'text/html':
                html_text = content
            found_urls = re.findall(URL_REGEX, content)
            urls += [url for url in found_urls if 'safelinks.protection.outlook.com' not in url]
        except:
            pass

    combined_text = body_text
    if html_text:
        try:
            soup = BeautifulSoup(html_text, 'html.parser')
            combined_text += '\n' + soup.get_text(separator=' ', strip=True)
            combined_text = ''.join(c for c in combined_text if c.isprintable() or c.isspace())
        except:
            pass

    attachments = extract_attachments(msg, Path.cwd())

    for att in attachments:
        if att.get('pdf_urls'):
            urls += att['pdf_urls']

    urls = list(set(urls))
    ips = list(set(re.findall(IP_REGEX, combined_text)))
    domains = list(set(re.findall(DOMAIN_REGEX, combined_text)))
    emails = list(set(re.findall(EMAIL_REGEX, combined_text)))

    suspicious_flags = []
    for url in urls:
        try:
            parsed = urlparse(url)
            if re.match(IP_REGEX, parsed.netloc):
                suspicious_flags.append(f"IP-based URL: {url}")
            elif any(shortener in url for shortener in ['bit.ly', 'tinyurl', 'goo.gl']):
                suspicious_flags.append(f"URL shortener: {url}")
        except:
            pass

    json_output = {
        "sender_email": soc_info['From'],
        "recipient_email": soc_info['To'],
        "SPF_DKIM_DMARC_result": soc_info['Auth_Results'],
        "message": combined_text[:500] + ("..." if len(combined_text) > 500 else ""),
        "Network_ID": soc_info['Message-ID'],
        "sender_mail_from_address": soc_info['From'],
        "Return_Path": soc_info['Return-Path'],
        "other_details": {
            "Date": soc_info['Date'],
            "X-Mailer": soc_info['X-Mailer'],
            "X-Originating-IP": soc_info['X-Originating-IP'],
            "Reply-To": soc_info['Reply-To'],
            "Suspicious_Flags": suspicious_flags
        }
    }

    list_output = []
    if urls:
        list_output.append("++ [URL]")
        for i, url in enumerate(urls, 1):
            list_output.append(f"{i}. {url}")
    if attachments:
        list_output.append("\n++ HASH of Files")
        for i, att in enumerate(attachments, 1):
            list_output.append(f"{i}. MD5: {att['md5']}, SHA256: {att['sha256']}")
        list_output.append("\n++ Attachment file name")
        for i, att in enumerate(attachments, 1):
            list_output.append(f"{i}. {att['filename']}")
        image_attachments = [att['filename'] for att in attachments if att['is_image']]
        if image_attachments:
            list_output.append("\n++ image in attachment")
            for i, img in enumerate(image_attachments, 1):
                list_output.append(f"{i}. {img}")
    if ips:
        list_output.append("\n++ IP")
        for i, ip in enumerate(ips, 1):
            list_output.append(f"{i}. {ip}")

    return json_output, list_output

if __name__ == "__main__":
    eml_file = get_argument()
    json_output, list_output = extract_eml_info(eml_file.eml)
    if "error" in json_output:
        print(json_output["error"])
    else:
        print(json.dumps(json_output, indent=4))
        print("\n".join(list_output))

import os
import re
import shutil

import pytesseract
from PIL import Image, ImageOps, ImageEnhance, ImageFilter


# --------------------------------------------------
# TESSERACT OCR CONFIGURATION
# Supports Windows and Linux (Render)
# --------------------------------------------------

tesseract_path = (
    os.environ.get("TESSERACT_CMD")
    or shutil.which("tesseract")
)

# Windows fallback path
if not tesseract_path and os.name == "nt":
    windows_path = r"C:\Program Files\Tesseract-OCR\tesseract.exe"

    if os.path.exists(windows_path):
        tesseract_path = windows_path

if tesseract_path:
    pytesseract.pytesseract.tesseract_cmd = tesseract_path


# --------------------------------------------------
# EXTRACT TEXT FROM ENROLLMENT CARD
# --------------------------------------------------

def extract_card_text(image_path):

    image = Image.open(image_path).convert("RGB")

    # Image preprocessing for better OCR accuracy
    image = ImageOps.grayscale(image)
    image = ImageOps.autocontrast(image)

    image = image.resize(
        (image.width * 2, image.height * 2)
    )

    image = ImageEnhance.Contrast(image).enhance(2)
    image = image.filter(ImageFilter.SHARPEN)

    # Extract text using Tesseract
    text = pytesseract.image_to_string(
        image,
        config="--oem 3 --psm 11"
    )

    return text


# --------------------------------------------------
# EXTRACT ENROLLMENT NUMBER AND DEPARTMENT
# --------------------------------------------------

def extract_student_details(image_path):

    raw_text = extract_card_text(image_path)

    text = raw_text.upper()

    # Normalize hyphens and whitespace
    text = (
        text.replace("–", "-")
        .replace("—", "-")
        .replace("−", "-")
    )

    text = re.sub(r"\s+", " ", text)

    # Recognize enrollment formats:
    # 1350-CSE
    # 1351-SW
    # 1350CSE
    # 1351SW

    enrollment_match = re.search(
        r"\b(\d{4,})\s*-?\s*(CSE|SW)\b",
        text
    )

    enrollment_number = None

    if enrollment_match:
        enrollment_number = (
            enrollment_match.group(1)
            + "-"
            + enrollment_match.group(2)
        )

    # --------------------------------------------------
    # DEPARTMENT DETECTION
    # --------------------------------------------------

    department = None
    detected_department_label = None

    if "COMPUTER SYSTEMS ENGINEERING" in text:
        department = "COMPUTER SYSTEMS ENGINEERING"
        detected_department_label = department

    elif "SOFTWARE ENGINEERING" in text:
        department = "SOFTWARE ENGINEERING"
        detected_department_label = department

    elif "MECHANICAL ENGINEERING" in text or "MECHANICAL" in text:
        detected_department_label = "MECHANICAL ENGINEERING"

    elif "ELECTRICAL ENGINEERING" in text or "ELECTRICAL" in text:
        detected_department_label = "ELECTRICAL ENGINEERING"

    elif "CIVIL ENGINEERING" in text or "CIVIL" in text:
        detected_department_label = "CIVIL ENGINEERING"

    elif "CHEMICAL ENGINEERING" in text or "CHEMICAL" in text:
        detected_department_label = "CHEMICAL ENGINEERING"

    # --------------------------------------------------
    # RETURN OCR RESULTS
    # --------------------------------------------------

    return {
        "enrollment_number": enrollment_number,
        "department": department,
        "detected_department_label": detected_department_label,
        "raw_text": raw_text
    }

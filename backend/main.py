import sys
import os
import io

# 1. Add 'src' directory to Python path BEFORE importing local modules
BACKEND_DIR = os.path.dirname(os.path.abspath(__file__))
PROJECT_ROOT = os.path.dirname(BACKEND_DIR)
SRC_PATH = os.path.join(PROJECT_ROOT, "src")

if SRC_PATH not in sys.path:
    sys.path.insert(0, SRC_PATH)

# 2. Local module imports
from url_checker import analyze_url
from email_checker import analyze_message
from website_checker import analyze_website_info

# 3. Third-party library imports
from fastapi import FastAPI, UploadFile, File, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from PIL import Image, ImageEnhance, ImageOps
import pytesseract

# Set Tesseract executable path
pytesseract.pytesseract.tesseract_cmd = (
    r"C:\Users\Student\AppData\Local\Tesseract-OCR\tesseract.exe"
)

app = FastAPI(
    title="ScamShield API",
    description="Multi-vector heuristic fraud, phishing, and OCR detection engine",
    version="2.0.0"
)

# Enable CORS for the Vite frontend
app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://localhost:5173",
        "http://127.0.0.1:5173"
    ],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

class URLRequest(BaseModel):
    url: str

class MessageRequest(BaseModel):
    message: str

class WebsiteRequest(BaseModel):
    page_title: str
    page_text: str

def get_risk_level(risk_score: int) -> str:
    if risk_score == 0:
        return "CLEAN / BENIGN"
    elif risk_score < 35:
        return "ELEVATED CAUTION"
    elif risk_score < 65:
        return "SUSPICIOUS"
    return "CRITICAL PHISHING THREAT"

def extract_text_robust(image: Image.Image) -> str:
    """
    Multi-pass extraction:
    - Pass 1: Standard PSM 6 (uniform block of text)
    - Pass 2: Sparse text PSM 11 (catches buttons like 'UPDATE ACCOUNT NOW' and banners)
    - Pass 3: Inverted image for white text on colored banners/buttons
    """
    w, h = image.size
    upscaled = image.resize((w * 2, h * 2), Image.Resampling.LANCZOS)
    gray = upscaled.convert("L")
    enhancer = ImageEnhance.Contrast(gray)
    enhanced = enhancer.enhance(2.0)
    
    # Pass 1: standard block
    t1 = pytesseract.image_to_string(enhanced, config=r'--oem 3 --psm 6')
    # Pass 2: sparse text (isolated buttons and banners)
    t2 = pytesseract.image_to_string(enhanced, config=r'--oem 3 --psm 11')
    
    # Pass 3: inverted pass for white text on colored backgrounds
    inverted = ImageOps.invert(gray)
    t3 = pytesseract.image_to_string(inverted, config=r'--oem 3 --psm 11')
    
    return f"{t1}\n{t2}\n{t3}".strip()

@app.get("/")
def home():
    return {
        "message": "ScamShield Security Engine Active",
        "status": "running",
        "version": "2.0.0"
    }

@app.post("/analyze/url")
def analyze_url_endpoint(request: URLRequest):
    risk_score, warnings = analyze_url(request.url)
    return {
        "risk_score": risk_score,
        "risk_level": get_risk_level(risk_score),
        "warnings": warnings,
        "matched_phrases": [],
        "categories": ["URL Inspection"]
    }

@app.post("/analyze/message")
def analyze_message_endpoint(request: MessageRequest):
    result = analyze_message(request.message)
    if len(result) == 4:
        risk_score, warnings, matched_phrases, categories = result
    else:
        risk_score, warnings = result
        matched_phrases, categories = [], []

    return {
        "risk_score": risk_score,
        "risk_level": get_risk_level(risk_score),
        "warnings": warnings,
        "matched_phrases": matched_phrases,
        "categories": categories
    }

@app.post("/analyze/website")
def analyze_website_endpoint(request: WebsiteRequest):
    risk_score, warnings = analyze_website_info(
        request.page_title,
        request.page_text
    )
    return {
        "risk_score": risk_score,
        "risk_level": get_risk_level(risk_score),
        "warnings": warnings,
        "matched_phrases": [],
        "categories": ["Website Inspection"]
    }

@app.post("/analyze/screenshot")
async def analyze_screenshot_endpoint(file: UploadFile = File(...)):
    allowed_types = ["image/png", "image/jpeg", "image/webp"]
    if file.content_type not in allowed_types:
        raise HTTPException(
            status_code=400,
            detail="Please upload a valid PNG, JPG, or WEBP image."
        )

    image_data = await file.read()
    if not image_data:
        raise HTTPException(
            status_code=400,
            detail="The uploaded image file is empty."
        )

    try:
        image = Image.open(io.BytesIO(image_data))
        extracted_text = extract_text_robust(image)
        if not extracted_text:
            extracted_text = pytesseract.image_to_string(image).strip()
    except Exception as error:
        raise HTTPException(
            status_code=500,
            detail=f"OCR execution failure: {str(error)}"
        )

    if not extracted_text.strip():
        return {
            "risk_score": 0,
            "risk_level": "CLEAN / BENIGN",
            "warnings": ["No readable text could be identified in the screenshot."],
            "matched_phrases": [],
            "categories": ["OCR Analysis"]
        }

    result = analyze_message(extracted_text)
    if len(result) == 4:
        risk_score, warnings, matched_phrases, categories = result
    else:
        risk_score, warnings = result
        matched_phrases, categories = [], []

    clean_preview = " ".join(extracted_text.split())
    preview_snippet = clean_preview[:120] + "..." if len(clean_preview) > 120 else clean_preview
    warnings.insert(0, f"Extracted Text: {preview_snippet}")

    return {
        "risk_score": risk_score,
        "risk_level": get_risk_level(risk_score),
        "warnings": warnings,
        "matched_phrases": matched_phrases,
        "categories": categories
    }
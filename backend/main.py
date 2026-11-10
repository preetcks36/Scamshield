import sys
import os
import io
import shutil

# 1. Resolve path to ScamShield/src and add to sys.path first
BACKEND_DIR = os.path.dirname(os.path.abspath(__file__))
PROJECT_ROOT = os.path.dirname(BACKEND_DIR)
SRC_PATH = os.path.join(PROJECT_ROOT, "src")

if SRC_PATH not in sys.path:
    sys.path.insert(0, SRC_PATH)

# 2. Local module imports
from url_checker import analyze_url
from email_checker import analyze_message
from website_checker import analyze_website_info

# 3. Third-party imports
from fastapi import FastAPI, UploadFile, File, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from PIL import Image, ImageEnhance, ImageOps
import pytesseract

# 4. Dynamic Tesseract Binary Detection
system_tesseract = shutil.which("tesseract")
if system_tesseract:
    pytesseract.pytesseract.tesseract_cmd = system_tesseract
else:
    pytesseract.pytesseract.tesseract_cmd = (
        r"C:\Users\Student\AppData\Local\Tesseract-OCR\tesseract.exe"
    )

app = FastAPI(
    title="ScamShield API",
    description="Multi-vector heuristic fraud, phishing, and OCR detection engine",
    version="2.0.0"
)

# 5. Permissive CORS Middleware Configuration
origins = [
    "https://scamshield-wine.vercel.app",
    "http://localhost:5173",
    "http://127.0.0.1:5173",
    "*"
]

app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,
    allow_credentials=False,
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
    """Multi-pass extraction for standard text, buttons, and inverted banners."""
    w, h = image.size
    upscaled = image.resize((w * 2, h * 2), Image.Resampling.LANCZOS)
    gray = upscaled.convert("L")
    enhancer = ImageEnhance.Contrast(gray)
    enhanced = enhancer.enhance(2.0)
    
    t1 = pytesseract.image_to_string(enhanced, config=r'--oem 3 --psm 6')
    t2 = pytesseract.image_to_string(enhanced, config=r'--oem 3 --psm 11')
    
    inverted = ImageOps.invert(gray)
    t3 = pytesseract.image_to_string(inverted, config=r'--oem 3 --psm 11')
    
    return f"{t1}\n{t2}\n{t3}".strip()

@app.api_route("/", methods=["GET", "HEAD"])
def home():
    return {
        "message": "ScamShield Security Engine Active",
        "status": "running",
        "version": "2.0.0"
    }

@app.post("/analyze/url")
def analyze_url_endpoint(request: URLRequest):
    try:
        risk_score, warnings = analyze_url(request.url)
        return {
            "risk_score": risk_score,
            "risk_level": get_risk_level(risk_score),
            "warnings": warnings,
            "matched_phrases": [],
            "categories": ["URL Inspection"]
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"URL inspection error: {str(e)}")

@app.post("/analyze/message")
def analyze_message_endpoint(request: MessageRequest):
    try:
        raw_result = analyze_message(request.message)

        # Dynamic unpack supporting 4-element, 2-element, or custom returns
        if isinstance(raw_result, tuple) and len(raw_result) == 4:
            risk_score, warnings, matched_phrases, categories = raw_result
        elif isinstance(raw_result, tuple) and len(raw_result) == 2:
            risk_score, warnings = raw_result
            matched_phrases, categories = [], []
        else:
            risk_score, warnings, matched_phrases, categories = 0, [], [], []

        return {
            "risk_score": risk_score,
            "risk_level": get_risk_level(risk_score),
            "warnings": warnings,
            "matched_phrases": matched_phrases,
            "categories": categories
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Message analysis error: {str(e)}")

@app.post("/analyze/website")
def analyze_website_endpoint(request: WebsiteRequest):
    try:
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
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Website check error: {str(e)}")

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

    raw_result = analyze_message(extracted_text)
    if isinstance(raw_result, tuple) and len(raw_result) == 4:
        risk_score, warnings, matched_phrases, categories = raw_result
    elif isinstance(raw_result, tuple) and len(raw_result) == 2:
        risk_score, warnings = raw_result
        matched_phrases, categories = [], []
    else:
        risk_score, warnings, matched_phrases, categories = 0, [], [], []

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
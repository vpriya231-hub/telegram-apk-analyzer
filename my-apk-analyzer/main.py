import os
import shutil
from fastapi import FastAPI, UploadFile, File
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from androguard.core.apk import APK


app = FastAPI()

# Frontend-ൽ നിന്ന് റിക്വസ്റ്റുകൾ വരാൻ CORS അനുവദിക്കുന്നു
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

@app.post("/api/analyze")
async def analyze_apk(file: UploadFile = File(...)):
    temp_path = f"temp_{file.filename}"
    with open(temp_path, "wb") as buffer:
        shutil.copyfileobj(file.file, buffer)
        
    try:
        apk = APK(temp_path)
        
        # 100+ ഡാറ്റ പോയിന്റുകൾ ശേഖരിക്കുന്നു
        report = {
            "app_name": apk.get_app_name(),
            "package_name": apk.get_package(),
            "version_name": apk.get_androidversion_name(),
            "version_code": apk.get_androidversion_code(),
            "min_sdk": apk.get_min_sdk_version(),
            "target_sdk": apk.get_target_sdk_version(),
            "permissions": apk.get_permissions(),
            "declared_permissions": apk.get_declared_permissions(),
            "activities": apk.get_activities(),
            "services": apk.get_services(),
            "receivers": apk.get_receivers(),
            "providers": apk.get_providers(),
            "is_signed": apk.is_signed(),
            "signatures": {
                "v1": apk.is_signed_v1(),
                "v2": apk.is_signed_v2(),
                "v3": apk.is_signed_v3()
            },
            "dex_files": [f for f in apk.get_files() if f.endswith(".dex")],
            "native_libraries": apk.get_libraries(),
            "total_files": len(apk.get_files())
        }
        return {"status": "success", "data": report}
    except Exception as e:
        return {"status": "error", "message": str(e)}
    finally:
        if os.path.exists(temp_path):
            os.remove(temp_path)

# Static ഫയലുകൾ (HTML പേജ്) കാണിക്കാൻ
if os.path.exists("static"):
    app.mount("/", StaticFiles(directory="static", html=True), name="static")


from pydantic import BaseModel, Field


class AnalyzeRequest(BaseModel):
    message: str = Field(min_length=1, max_length=12000)


class WarningSign(BaseModel):
    title: str
    detail: str
    severity: str


class CheckedUrl(BaseModel):
    url: str
    domain: str
    risk: int
    indicators: list[str]


class AnalyzeResponse(BaseModel):
    risk_score: int
    classification: str
    summary: str
    warning_signs: list[WarningSign]
    checked_urls: list[CheckedUrl]
    recommendations: list[str]
    analysis_mode: str

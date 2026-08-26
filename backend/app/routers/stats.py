from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session
from sqlalchemy import func
from typing import Dict, Any, List
from app.database import get_db
from app.models.models import Email, EmailAnalysis, Indicator, Alert, User
from app.schemas.schemas import DashboardStats, AlertResponse
from app.auth.deps import get_current_user

router = APIRouter(prefix="/stats", tags=["SOC Dashboard Telemetry"])

@router.get("/dashboard", response_model=DashboardStats)
def get_dashboard_telemetry(db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    total_analyzed = db.query(Email).count()
    
    # Accurate severity breakdown based on deterministic 0-100 scores
    safe_count = db.query(EmailAnalysis).filter(EmailAnalysis.risk_score < 30).count()
    suspicious_count = db.query(EmailAnalysis).filter(EmailAnalysis.risk_score >= 30, EmailAnalysis.risk_score < 70).count()
    high_risk_count = db.query(EmailAnalysis).filter(EmailAnalysis.risk_score >= 70, EmailAnalysis.risk_score < 90).count()
    critical_count = db.query(EmailAnalysis).filter(EmailAnalysis.risk_score >= 90).count()

    open_cases = 0
    active_campaigns = 0
    total_iocs = db.query(Indicator).count()

    # Risk Distribution
    risk_distribution = [
        {"name": "Safe (0-29)", "count": safe_count, "color": "#10b981"},
        {"name": "Suspicious (30-69)", "count": suspicious_count, "color": "#f59e0b"},
        {"name": "High Risk (70-89)", "count": high_risk_count, "color": "#f97316"},
        {"name": "Critical (90-100)", "count": critical_count, "color": "#ef4444"},
    ]

    # Threat Trends (group by day)
    threat_trends = [
        {"date": "Day -6", "threats": 0, "safe": 0, "total": 0},
        {"date": "Day -5", "threats": 0, "safe": 0, "total": 0},
        {"date": "Day -4", "threats": 0, "safe": 0, "total": 0},
        {"date": "Day -3", "threats": 0, "safe": 0, "total": 0},
        {"date": "Day -2", "threats": 0, "safe": 0, "total": 0},
        {"date": "Day -1", "threats": 0, "safe": 0, "total": 0},
        {"date": "Today", "threats": suspicious_count + high_risk_count + critical_count, "safe": safe_count, "total": total_analyzed},
    ]

    # Top Malicious Domains
    top_domains_query = (
        db.query(Indicator.value, func.count(Indicator.id).label("count"))
        .filter(Indicator.ioc_type == "URL", Indicator.risk_score >= 30)
        .group_by(Indicator.value)
        .order_by(func.count(Indicator.id).desc())
        .limit(5)
        .all()
    )
    top_malicious_domains = [{"domain": row[0], "count": row[1]} for row in top_domains_query]

    # Top Suspicious IPs
    top_ips_query = (
        db.query(Indicator.value, func.count(Indicator.id).label("count"))
        .filter(Indicator.ioc_type == "IP")
        .group_by(Indicator.value)
        .order_by(func.count(Indicator.id).desc())
        .limit(5)
        .all()
    )
    top_suspicious_ips = [{"ip": row[0], "count": row[1]} for row in top_ips_query]

    # Recent Alerts
    recent_alerts = db.query(Alert).order_by(Alert.created_at.desc()).limit(6).all()

    return {
        "total_analyzed": total_analyzed,
        "safe_count": safe_count,
        "suspicious_count": suspicious_count,
        "high_risk_count": high_risk_count,
        "critical_count": critical_count,
        "open_cases_count": open_cases,
        "active_campaigns_count": active_campaigns,
        "total_iocs_count": total_iocs,
        "threat_trends": threat_trends,
        "risk_distribution": risk_distribution,
        "top_malicious_domains": top_malicious_domains,
        "top_suspicious_ips": top_suspicious_ips,
        "recent_alerts": recent_alerts
    }

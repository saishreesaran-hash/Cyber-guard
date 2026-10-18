"""Tests for anomaly_detector module."""

import json
import pandas as pd
import pytest

from modules.anomaly_detector import (
    analyze_apps,
    build_mock_app_list,
    load_app_data,
)


def test_build_mock_app_list():
    df = build_mock_app_list()
    assert isinstance(df, pd.DataFrame)
    assert len(df) == 15
    assert "app_name" in df.columns
    assert "has_sms_permission" in df.columns


def test_analyze_apps_mock_list():
    df = build_mock_app_list()
    out = analyze_apps(df)
    assert "results" in out
    assert "summary" in out
    summary = out["summary"]
    assert summary["total_apps"] == 15
    assert summary["high_risk"] > 0
    assert summary["safe"] > 0
    assert "assessment_type" in summary

    results = out["results"]
    assert "anomaly_score" in results.columns
    assert "risk_level" in results.columns
    assert "reason" in results.columns


def test_load_app_data_csv():
    csv_content = """app_name,has_sms_permission,has_camera_permission,has_contacts_permission,background_data_usage_mb,overlay_permission
TestApp1,0,1,0,25.5,0
TestApp2,1,1,1,450.0,1
"""
    df = load_app_data(csv_content, "apps.csv")
    assert len(df) == 2
    assert df.iloc[0]["app_name"] == "TestApp1"
    assert df.iloc[1]["background_data_usage_mb"] == 450.0


def test_load_app_data_boolean_strings():
    csv_content = """app_name,has_sms_permission,has_camera_permission,has_contacts_permission,background_data_usage_mb,overlay_permission
AppA,no,yes,false,15,0
AppB,yes,true,1,120,true
"""
    df = load_app_data(csv_content, "apps.csv")
    assert df.iloc[0]["has_sms_permission"] == 0.0
    assert df.iloc[0]["has_camera_permission"] == 1.0
    assert df.iloc[1]["overlay_permission"] == 1.0


def test_load_app_data_json():
    json_data = [
        {
            "app_name": "WeatherApp",
            "has_sms_permission": 0,
            "has_camera_permission": 0,
            "has_contacts_permission": 0,
            "background_data_usage_mb": 5,
            "overlay_permission": 0,
        }
    ]
    df = load_app_data(json.dumps(json_data), "apps.json")
    assert len(df) == 1
    assert df.iloc[0]["app_name"] == "WeatherApp"


def test_load_app_data_missing_column():
    csv_bad = """app_name,has_sms_permission
App1,0
"""
    with pytest.raises(ValueError, match="Missing required columns"):
        load_app_data(csv_bad, "bad.csv")


def test_load_app_data_empty():
    with pytest.raises(ValueError, match="empty"):
        load_app_data("", "empty.csv")


def test_load_app_data_negative_data():
    csv_negative = """app_name,has_sms_permission,has_camera_permission,has_contacts_permission,background_data_usage_mb,overlay_permission
BadApp,0,0,0,-50,0
"""
    with pytest.raises(ValueError, match="cannot be negative"):
        load_app_data(csv_negative, "bad.csv")

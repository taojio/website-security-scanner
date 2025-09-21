import os
import json
import datetime
import smtplib
import logging
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from email.mime.application import MIMEApplication
from typing import Dict, Any, Optional, List, Tuple

# 设置日志
def setup_logging():
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
        handlers=[
            logging.FileHandler("report_generator.log"),
            logging.StreamHandler()
        ]
    )

setup_logging()
logger = logging.getLogger("ReportGenerator")


class ReportGenerator:
    """安全扫描报告生成器
    
    支持多语言模板、自动化生成与分发策略
    """
    
    def __init__(self, scan_results: Dict[str, Any], target_url: str, language: str = 'zh-CN'):
        """
        初始化报告生成器
        
        Args:
            scan_results: 扫描结果
            target_url: 目标URL
            language: 报告语言 ('zh-CN', 'en-US'等)
        """
        self.scan_results = scan_results
        self.target_url = target_url
        self.timestamp = datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        self.language = language
        
        # 多语言支持
        self._init_translations()
        
        # 模板目录
        self.templates_dir = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), 'templates')
        
        # 确保模板目录存在
        if not os.path.exists(self.templates_dir):
            os.makedirs(self.templates_dir)
            self._create_default_templates()
            
    def _init_translations(self):
        """
        初始化多语言翻译字典，支持中、英、日、韩、法、德六种语言
        """
        self.translations = {
            'zh-CN': {
                'report_title': '网站安全扫描报告',
                'target': '目标地址',
                'scan_time': '扫描时间',
                'report_level': '报告级别',
                'summary': '摘要',
                'total_vulnerabilities': '总漏洞数',
                'total_modules': '扫描模块数',
                'vulnerability_overview': '漏洞概览',
                'detailed_results': '详细结果',
                'error': '错误',
                'no_vulnerabilities': '未发现相关漏洞',
                'result_format_error': '模块返回结果格式不正确',
                'severity': '风险等级',
                'description': '描述',
                'evidence': '证据',
                'recommendation': '修复建议',
                'report_level_basic': '基础检测 - 涵盖基本的安全检测项，快速扫描常见问题',
                'report_level_standard': '一般检测 - 在基础检测之上增加中等复杂度的检测项，覆盖更多潜在风险',
                'report_level_comprehensive': '全面检测 - 执行完整的深度扫描，包括所有检测项，适用于高安全性需求场景',
                'scan_summary': '扫描总结',
                'vulnerability_distribution': '漏洞分布',
                'recommendation_summary': '修复建议摘要',
                'no_recommendations': '未提供具体修复建议',
                'critical': '严重',
                'high': '高危',
                'medium': '中危',
                'low': '低危',
                'unknown': '未知',
                'vulnerability_types': '漏洞类型',
                'scan_duration': '扫描时长',
                'scan_status': '扫描状态',
                'success': '成功',
                'failed': '失败',
                'partial': '部分完成',
                'risk_assessment': '风险评估',
                'security_rating': '安全评分',
                'remediation_guide': '修复指南',
                'reference_links': '参考链接',
                'vulnerability_details': '漏洞详情',
                'affected_components': '受影响组件',
                'attack_vector': '攻击向量',
                'cvss_score': 'CVSS评分',
                'cve_id': 'CVE编号',
                'exploitability': '可利用性',
                'mitigation': '缓解措施',
                'patch_available': '补丁可用',
                'compliance_check': '合规检查',
                'passed': '通过',
                'failed': '未通过',
                'warning': '警告',
                'pending': '待处理',
                'false_positive': '误报',
                'confirmed': '已确认',
                'new_vulnerabilities': '新增漏洞',
                'fixed_vulnerabilities': '已修复漏洞',
                'persistent_vulnerabilities': '持续存在漏洞'
            },
            'en-US': {
                'report_title': 'Website Security Scan Report',
                'target': 'Target URL',
                'scan_time': 'Scan Time',
                'report_level': 'Report Level',
                'summary': 'Summary',
                'total_vulnerabilities': 'Total Vulnerabilities',
                'total_modules': 'Total Modules',
                'vulnerability_overview': 'Vulnerability Overview',
                'detailed_results': 'Detailed Results',
                'error': 'Error',
                'no_vulnerabilities': 'No vulnerabilities found',
                'result_format_error': 'Module result format incorrect',
                'severity': 'Severity',
                'description': 'Description',
                'evidence': 'Evidence',
                'recommendation': 'Recommendation',
                'report_level_basic': 'Basic - Covers basic security checks, quick scan for common issues',
                'report_level_standard': 'Standard - Adds medium complexity checks on top of basic, covers more potential risks',
                'report_level_comprehensive': 'Comprehensive - Performs full deep scan, includes all checks, suitable for high security requirements',
                'scan_summary': 'Scan Summary',
                'vulnerability_distribution': 'Vulnerability Distribution',
                'recommendation_summary': 'Recommendation Summary',
                'no_recommendations': 'No specific recommendations provided',
                'critical': 'Critical',
                'high': 'High',
                'medium': 'Medium',
                'low': 'Low',
                'unknown': 'Unknown',
                'vulnerability_types': 'Vulnerability Types',
                'scan_duration': 'Scan Duration',
                'scan_status': 'Scan Status',
                'success': 'Success',
                'failed': 'Failed',
                'partial': 'Partially Completed',
                'risk_assessment': 'Risk Assessment',
                'security_rating': 'Security Rating',
                'remediation_guide': 'Remediation Guide',
                'reference_links': 'Reference Links',
                'vulnerability_details': 'Vulnerability Details',
                'affected_components': 'Affected Components',
                'attack_vector': 'Attack Vector',
                'cvss_score': 'CVSS Score',
                'cve_id': 'CVE ID',
                'exploitability': 'Exploitability',
                'mitigation': 'Mitigation',
                'patch_available': 'Patch Available',
                'compliance_check': 'Compliance Check',
                'passed': 'Passed',
                'failed': 'Failed',
                'warning': 'Warning',
                'pending': 'Pending',
                'false_positive': 'False Positive',
                'confirmed': 'Confirmed',
                'new_vulnerabilities': 'New Vulnerabilities',
                'fixed_vulnerabilities': 'Fixed Vulnerabilities',
                'persistent_vulnerabilities': 'Persistent Vulnerabilities'
            },
            'ja-JP': {
                'report_title': 'ウェブサイトセキュリティスキャンレポート',
                'target': 'ターゲットURL',
                'scan_time': 'スキャン時間',
                'report_level': 'レポートレベル',
                'summary': '概要',
                'total_vulnerabilities': '総脆弱性数',
                'total_modules': 'スキャンモジュール数',
                'vulnerability_overview': '脆弱性概要',
                'detailed_results': '詳細結果',
                'error': 'エラー',
                'no_vulnerabilities': '脆弱性は検出されませんでした',
                'result_format_error': 'モジュールの結果形式が正しくありません',
                'severity': '深刻度',
                'description': '説明',
                'evidence': '証拠',
                'recommendation': '推奨事項',
                'report_level_basic': '基本 - 基本的なセキュリティチェックをカバー、一般的な問題の迅速なスキャン',
                'report_level_standard': '標準 - 基本に中程度の複雑さのチェックを追加、より多くの潜在的なリスクをカバー',
                'report_level_comprehensive': '包括的 - 完全な深度スキャンを実行、すべてのチェックを含み、高セキュリティ要件に適しています',
                'scan_summary': 'スキャンサマリー',
                'vulnerability_distribution': '脆弱性分布',
                'recommendation_summary': '推奨事項サマリー',
                'no_recommendations': '具体的な推奨事項は提供されていません',
                'critical': '重大',
                'high': '高',
                'medium': '中',
                'low': '低',
                'unknown': '未知',
                'vulnerability_types': '脆弱性の種類',
                'scan_duration': 'スキャン期間',
                'scan_status': 'スキャンステータス',
                'success': '成功',
                'failed': '失敗',
                'partial': '部分的に完了',
                'risk_assessment': 'リスク評価',
                'security_rating': 'セキュリティ評価',
                'remediation_guide': '修復ガイド',
                'reference_links': '参照リンク',
                'vulnerability_details': '脆弱性の詳細',
                'affected_components': '影響を受けるコンポーネント',
                'attack_vector': '攻撃ベクトル',
                'cvss_score': 'CVSSスコア',
                'cve_id': 'CVE ID',
                'exploitability': '悪用可能性',
                'mitigation': '緩和策',
                'patch_available': 'パッチ利用可能',
                'compliance_check': 'コンプライアンスチェック',
                'passed': '合格',
                'failed': '不合格',
                'warning': '警告',
                'pending': '保留中',
                'false_positive': '誤検知',
                'confirmed': '確認済み',
                'new_vulnerabilities': '新しい脆弱性',
                'fixed_vulnerabilities': '修正済みの脆弱性',
                'persistent_vulnerabilities': '継続的な脆弱性'
            },
            'ko-KR': {
                'report_title': '웹사이트 보안 스캔 보고서',
                'target': '대상 URL',
                'scan_time': '스캔 시간',
                'report_level': '보고서 수준',
                'summary': '요약',
                'total_vulnerabilities': '총 취약점 수',
                'total_modules': '스캔 모듈 수',
                'vulnerability_overview': '취약점 개요',
                'detailed_results': '상세 결과',
                'error': '오류',
                'no_vulnerabilities': '취약점이 발견되지 않았습니다',
                'result_format_error': '모듈 결과 형식이 올바르지 않습니다',
                'severity': '심각도',
                'description': '설명',
                'evidence': '증거',
                'recommendation': '권장 사항',
                'report_level_basic': '기본 - 기본적인 보안 검사를 포함, 일반적인 문제에 대한 빠른 스캔',
                'report_level_standard': '표준 - 기본에 중간 복잡도의 검사를 추가, 더 많은 잠재적 위험을 포함',
                'report_level_comprehensive': '포괄적 - 전체 심층 스캔을 실행, 모든 검사를 포함, 높은 보안 요구사항에 적합',
                'scan_summary': '스캔 요약',
                'vulnerability_distribution': '취약점 분포',
                'recommendation_summary': '권장 사항 요약',
                'no_recommendations': '구체적인 권장 사항이 제공되지 않았습니다',
                'critical': '심각',
                'high': '고위험',
                'medium': '중위험',
                'low': '저위험',
                'unknown': '알 수 없음',
                'vulnerability_types': '취약점 유형',
                'scan_duration': '스캔 기간',
                'scan_status': '스캔 상태',
                'success': '성공',
                'failed': '실패',
                'partial': '부분적으로 완료됨',
                'risk_assessment': '위험 평가',
                'security_rating': '보안 등급',
                'remediation_guide': '수정 가이드',
                'reference_links': '참조 링크',
                'vulnerability_details': '취약점 세부 사항',
                'affected_components': '영향을 받는 구성 요소',
                'attack_vector': '공격 벡터',
                'cvss_score': 'CVSS 점수',
                'cve_id': 'CVE ID',
                'exploitability': '이용 가능성',
                'mitigation': '완화 조치',
                'patch_available': '패치 사용 가능',
                'compliance_check': '준수 검사',
                'passed': '합격',
                'failed': '불합격',
                'warning': '경고',
                'pending': '대기 중',
                'false_positive': '오탐',
                'confirmed': '확인됨',
                'new_vulnerabilities': '새로운 취약점',
                'fixed_vulnerabilities': '수정된 취약점',
                'persistent_vulnerabilities': '지속적인 취약점'
            },
            'fr-FR': {
                'report_title': 'Rapport de scan de sécurité du site web',
                'target': 'URL cible',
                'scan_time': 'Heure du scan',
                'report_level': 'Niveau de rapport',
                'summary': 'Résumé',
                'total_vulnerabilities': 'Vulnérabilités totales',
                'total_modules': 'Modules de scan',
                'vulnerability_overview': 'Aperçu des vulnérabilités',
                'detailed_results': 'Résultats détaillés',
                'error': 'Erreur',
                'no_vulnerabilities': 'Aucune vulnérabilité trouvée',
                'result_format_error': 'Format de résultat de module incorrect',
                'severity': 'Gravité',
                'description': 'Description',
                'evidence': 'Preuve',
                'recommendation': 'Recommandation',
                'report_level_basic': 'De base - Couvre les vérifications de sécurité de base, scan rapide pour les problèmes courants',
                'report_level_standard': 'Standard - Ajoute des vérifications de complexité moyenne sur la base de base, couvre plus de risques potentiels',
                'report_level_comprehensive': 'Complet - Effectue un scan approfondi complet, inclut toutes les vérifications, adapté aux besoins de sécurité élevés',
                'scan_summary': 'Résumé du scan',
                'vulnerability_distribution': 'Distribution des vulnérabilités',
                'recommendation_summary': 'Résumé des recommandations',
                'no_recommendations': 'Aucune recommandation spécifique fournie',
                'critical': 'Critique',
                'high': 'Haute',
                'medium': 'Moyenne',
                'low': 'Basse',
                'unknown': 'Inconnu',
                'vulnerability_types': 'Types de vulnérabilités',
                'scan_duration': 'Durée du scan',
                'scan_status': 'Statut du scan',
                'success': 'Succès',
                'failed': 'Échec',
                'partial': 'Partiellement terminé',
                'risk_assessment': 'Évaluation des risques',
                'security_rating': 'Note de sécurité',
                'remediation_guide': 'Guide de remédiation',
                'reference_links': 'Liens de référence',
                'vulnerability_details': 'Détails des vulnérabilités',
                'affected_components': 'Composants affectés',
                'attack_vector': 'Vecteur d\'attaque',
                'cvss_score': 'Score CVSS',
                'cve_id': 'ID CVE',
                'exploitability': 'Exploitabilité',
                'mitigation': 'Atténuation',
                'patch_available': 'Patch disponible',
                'compliance_check': 'Vérification de conformité',
                'passed': 'Reussi',
                'failed': 'Échoué',
                'warning': 'Avertissement',
                'pending': 'En attente',
                'false_positive': 'Faux positif',
                'confirmed': 'Confirmé',
                'new_vulnerabilities': 'Nouvelles vulnérabilités',
                'fixed_vulnerabilities': 'Vulnérabilités corrigées',
                'persistent_vulnerabilities': 'Vulnérabilités persistantes'
            },
            'de-DE': {
                'report_title': 'Websicherheits-Scanbericht',
                'target': 'Ziel-URL',
                'scan_time': 'Scanzeit',
                'report_level': 'Berichtsebene',
                'summary': 'Zusammenfassung',
                'total_vulnerabilities': 'Gesamte Schwachstellen',
                'total_modules': 'Scanmodule',
                'vulnerability_overview': 'Schwachstellenübersicht',
                'detailed_results': 'Detaillierte Ergebnisse',
                'error': 'Fehler',
                'no_vulnerabilities': 'Keine Schwachstellen gefunden',
                'result_format_error': 'Modulresultatformat ist nicht korrekt',
                'severity': 'Schweregrad',
                'description': 'Beschreibung',
                'evidence': 'Beweis',
                'recommendation': 'Empfehlung',
                'report_level_basic': 'Grundlegend - Deckt grundlegende Sicherheitschecks ab, schneller Scan für häufige Probleme',
                'report_level_standard': 'Standard - Fügt Checks mittlerer Komplexität auf Basis des Grundlegendes hinzu, deckt mehr potenzielle Risiken ab',
                'report_level_comprehensive': 'Umfassend - Führt einen vollen Tiefenscan durch, umfasst alle Checks, geeignet für hohe Sicherheitsanforderungen',
                'scan_summary': 'Scanzusammenfassung',
                'vulnerability_distribution': 'Schwachstellungsverteilung',
                'recommendation_summary': 'Empfehlungszusammenfassung',
                'no_recommendations': 'Keine spezifischen Empfehlungen bereitgestellt',
                'critical': 'Kritisch',
                'high': 'Hoch',
                'medium': 'Mittel',
                'low': 'Niedrig',
                'unknown': 'Unbekannt',
                'vulnerability_types': 'Schwachstellentypen',
                'scan_duration': 'Scandauer',
                'scan_status': 'Scanstatus',
                'success': 'Erfolgreich',
                'failed': 'Gescheitert',
                'partial': 'Teilweise abgeschlossen',
                'risk_assessment': 'Risikobewertung',
                'security_rating': 'Sicherheitsbewertung',
                'remediation_guide': 'Behebungshandbuch',
                'reference_links': 'Referenzlinks',
                'vulnerability_details': 'Schwachstellendetails',
                'affected_components': 'Betroffene Komponenten',
                'attack_vector': 'Angriffvektor',
                'cvss_score': 'CVSS-Bewertung',
                'cve_id': 'CVE-ID',
                'exploitability': 'Exploitierbarkeit',
                'mitigation': 'Abschwächung',
                'patch_available': 'Patch verfügbar',
                'compliance_check': 'Compliance-Check',
                'passed': 'Bestanden',
                'failed': 'Nicht bestanden',
                'warning': 'Warnung',
                'pending': 'Ausstehend',
                'false_positive': 'Falsch positiv',
                'confirmed': 'Bestätigt',
                'new_vulnerabilities': 'Neue Schwachstellen',
                'fixed_vulnerabilities': 'Behobene Schwachstellen',
                'persistent_vulnerabilities': 'Persistente Schwachstellen'
            }
        }
        
        # 如果指定的语言不存在，使用默认语言(中文)
        if self.language not in self.translations:
            self.language = 'zh-CN'
            logger.warning(f'Language {self.language} not supported, using default language zh-CN')
            
    def _translate(self, key: str) -> str:
        """
        获取指定键的翻译文本
        
        Args:
            key: 翻译键
            
        Returns:
            str: 翻译后的文本
        """
        return self.translations[self.language].get(key, key)
            
    def _create_default_templates(self):
        """
        创建默认模板文件
        """
        # 这里简化处理，实际应用中应创建完整的模板文件
        logger.info('Creating default report templates')
    
    def generate_html_report(self, output_path: str, report_level: str = "basic"):
        """
        生成HTML格式报告
        
        Args:
            output_path: 输出文件路径
            report_level: 报告级别 ("basic", "standard", "comprehensive")
        
        Returns:
            bool: 生成是否成功
        """
        if not self.scan_results:
            logger.warning('No scan results available for report generation')
            return False
        
        try:
            # 生成HTML内容
            html_content = self._generate_html_content(report_level)
            
            # 确保输出目录存在
            output_dir = os.path.dirname(output_path)
            if output_dir and not os.path.exists(output_dir):
                os.makedirs(output_dir)
            
            # 写入文件
            with open(output_path, 'w', encoding='utf-8') as f:
                f.write(html_content)
            
            logger.info(f'HTML report generated successfully: {output_path}')
            return True
        except Exception as e:
            logger.error(f'Failed to generate HTML report: {str(e)}')
            return False
    
    def _generate_html_content(self, report_level: str = "basic") -> str:
        """生成HTML内容"""
        translations = self.translations[self.language]
        
        # 根据报告级别过滤结果
        filtered_results = self._filter_results_by_level(self.scan_results, report_level)
        
        # 统计漏洞数量
        total_vulnerabilities = 0
        vulnerability_summary = {}
        
        for module, results in filtered_results.items():
            if isinstance(results, dict) and 'vulnerabilities' in results:
                count = len(results['vulnerabilities'])
                vulnerability_summary[module] = count
                total_vulnerabilities += count
            else:
                vulnerability_summary[module] = 0
        
        html = f"""<!DOCTYPE html>
<html lang="{self.language}">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>{translations['report_title']}</title>
    <style>
        body {{
            font-family: Arial, sans-serif;
            margin: 20px;
            background-color: #f5f5f5;
        }}
        .container {{
            max-width: 1200px;
            margin: 0 auto;
            background-color: white;
            padding: 20px;
            border-radius: 8px;
            box-shadow: 0 2px 10px rgba(0,0,0,0.1);
        }}
        h1, h2, h3 {{
            color: #333;
        }}
        .header {{
            border-bottom: 2px solid #007bff;
            padding-bottom: 10px;
            margin-bottom: 20px;
        }}
        .summary {{
            background-color: #e9ecef;
            padding: 15px;
            border-radius: 5px;
            margin-bottom: 20px;
        }}
        .summary-item {{
            display: inline-block;
            margin-right: 20px;
            font-weight: bold;
        }}
        .vulnerability {{
            border: 1px solid #ddd;
            border-radius: 5px;
            margin-bottom: 15px;
            padding: 15px;
        }}
        .critical {{
            border-left: 5px solid #dc3545;
        }}
        .high {{
            border-left: 5px solid #fd7e14;
        }}
        .medium {{
            border-left: 5px solid #ffc107;
        }}
        .low {{
            border-left: 5px solid #28a745;
        }}
        .module-section {{
            margin-bottom: 30px;
        }}
        .module-header {{
            background-color: #007bff;
            color: white;
            padding: 10px;
            border-radius: 5px;
            margin-bottom: 15px;
        }}
        .error {{
            background-color: #f8d7da;
            color: #721c24;
            border: 1px solid #f5c6cb;
            padding: 10px;
            border-radius: 5px;
            margin-bottom: 15px;
        }}
        pre {{
            background-color: #f8f9fa;
            padding: 10px;
            border-radius: 3px;
            overflow-x: auto;
        }}
        .report-level {{
            background-color: #d4edda;
            border: 1px solid #c3e6cb;
            padding: 10px;
            border-radius: 5px;
            margin-bottom: 15px;
        }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>{translations['report_title']}</h1>
            <p>{translations['target']}: {self.target_url}</p>
            <p>{translations['scan_time']}: {self.timestamp}</p>
        </div>
        
        <div class="report-level">
            <strong>{translations['report_level']}:</strong> {self._get_report_level_description(report_level)}
        </div>
        
        <div class="summary">
            <div class="summary-item">{translations['total_vulnerabilities']}: {total_vulnerabilities}</div>
            <div class="summary-item">{translations['total_modules']}: {len(filtered_results)}</div>
        </div>
        
        <h2>{translations['vulnerability_overview']}</h2>
        <ul>
"""
        
        for module, count in vulnerability_summary.items():
            severity_class = "low" if count == 0 else "medium"
            html += f'            <li class="{severity_class}">{module}: {count} 个漏洞</li>\n'
        
        html += '        </ul>\n\n'
        html += '        <h2>详细结果</h2>\n'
        
        # 添加每个模块的详细结果
        for module, results in filtered_results.items():
            html += f'        <div class="module-section">\n'
            html += f'            <div class="module-header">\n'
            html += f'                <h3>{module.upper()} 检测</h3>\n'
            html += f'            </div>\n'
            
            if "error" in results:
                html += f'            <div class="error">\n'
                html += f'                <strong>错误:</strong> {results["error"]}\n'
                html += f'            </div>\n'
            elif isinstance(results, dict) and 'vulnerabilities' in results:
                if results['vulnerabilities']:
                    for vuln in results['vulnerabilities']:
                        severity = vuln.get('severity', 'low').lower()
                        html += f'            <div class="vulnerability {severity}">\n'
                        html += f'                <h4>{vuln.get("title", "未知漏洞")}</h4>\n'
                        html += f'                <p><strong>风险等级:</strong> {vuln.get("severity", "未知")}</p>\n'
                        html += f'                <p><strong>描述:</strong> {vuln.get("description", "无描述")}</p>\n'
                        
                        # 只在全面检测级别显示证据和修复建议
                        if report_level == "comprehensive":
                            if 'evidence' in vuln:
                                html += f'                <p><strong>证据:</strong></p>\n'
                                html += f'                <pre>{vuln["evidence"]}</pre>\n'
                            
                            if 'recommendation' in vuln:
                                html += f'                <p><strong>修复建议:</strong> {vuln["recommendation"]}</p>\n'
                        
                        html += f'            </div>\n'
                else:
                    html += f'            <p>未发现 {module} 相关漏洞</p>\n'
            else:
                html += f'            <p>模块返回结果格式不正确</p>\n'
            
            html += f'        </div>\n'
        
        html += """
    </div>
</body>
</html>"""
        
        return html

    def _filter_results_by_level(self, results: Dict[str, Any], level: str) -> Dict[str, Any]:
        """
        根据报告级别过滤结果
        
        Args:
            results: 扫描结果
            level: 报告级别 ("basic", "standard", "comprehensive")
            
        Returns:
            过滤后的结果
        """
        if level == "comprehensive":
            # 全面检测 - 返回所有结果
            return results
        elif level == "standard":
            # 一般检测 - 只返回有漏洞或错误的模块
            filtered = {}
            for module, data in results.items():
                if isinstance(data, dict):
                    if 'error' in data or ('vulnerabilities' in data and data['vulnerabilities']):
                        filtered[module] = data
                else:
                    filtered[module] = data
            return filtered
        else:
            # 基础检测 - 只返回有漏洞的模块
            filtered = {}
            for module, data in results.items():
                if isinstance(data, dict) and 'vulnerabilities' in data and data['vulnerabilities']:
                    filtered[module] = data
            return filtered

    def _get_report_level_description(self, level: str) -> str:
        """
        获取报告级别的多语言描述
        
        Args:
            level: 报告级别
        
        Returns:
            报告级别的描述文本
        """
        # 直接从翻译字典获取对应语言的报告级别描述
        try:
            return self.translations[self.language].get(f'report_level_{level}', level)
        except KeyError:
            # 如果当前语言没有对应的描述，返回默认英文描述
            default_descriptions = {
                'basic': 'Basic',
                'standard': 'Standard',
                'comprehensive': 'Comprehensive'
            }
            return default_descriptions.get(level, level)

    def _report_level_description(self, level: str) -> str:
        """
        兼容旧版的报告级别描述方法
        
        Args:
            level: 报告级别
        
        Returns:
            报告级别的中文描述
        """
        # 直接调用_get_report_level_description方法以保持一致性
        return self._get_report_level_description(level)
    
    def send_report_by_email(self, recipients: List[str], smtp_config: Dict[str, str], report_path: str) -> bool:
        """
        通过邮件发送扫描报告
        
        Args:
            recipients: 收件人邮箱列表
            smtp_config: SMTP配置
            report_path: 报告文件路径
        
        Returns:
            bool: 发送是否成功
        """
        try:
            # 创建邮件对象
            msg = MIMEMultipart()
            msg['From'] = smtp_config.get('from', 'security-scanner@example.com')
            msg['To'] = ', '.join(recipients)
            msg['Subject'] = f"{self.translations[self.language]['report_title']} - {self.target_url}"
            
            # 添加邮件正文
            body = f"""
            {self.translations[self.language]['report_title']}
            
            {self.translations[self.language]['target']}: {self.target_url}
            {self.translations[self.language]['scan_time']}: {self.timestamp}
            {self.translations[self.language]['report_level']}: {self._get_report_level_description('comprehensive')}
            
            请查看附件获取完整扫描报告。
            """
            msg.attach(MIMEText(body, 'plain'))
            
            # 添加报告附件
            if os.path.exists(report_path):
                with open(report_path, 'rb') as f:
                    part = MIMEApplication(f.read(), Name=os.path.basename(report_path))
                    part['Content-Disposition'] = f'attachment; filename="{os.path.basename(report_path)}"'
                    msg.attach(part)
            else:
                logger.error(f'Report file not found: {report_path}')
                return False
            
            # 发送邮件
            with smtplib.SMTP(smtp_config.get('server', 'localhost'), smtp_config.get('port', 25)) as server:
                if smtp_config.get('use_tls', False):
                    server.starttls()
                if 'username' in smtp_config and 'password' in smtp_config:
                    server.login(smtp_config['username'], smtp_config['password'])
                server.send_message(msg)
            
            logger.info(f'Report email sent successfully to {recipients}')
            return True
        except Exception as e:
            logger.error(f'Failed to send report email: {str(e)}')
            return False
    
    def publish_to_dashboard(self, dashboard_config: Dict[str, Any]) -> bool:
        """
        发布报告到安全仪表盘
        
        Args:
            dashboard_config: 仪表盘配置
        
        Returns:
            bool: 发布是否成功
        """
        try:
            # 这里是与安全仪表盘系统集成的预留接口
            # 实际应用中应实现与具体安全仪表盘的API集成
            logger.info('Report published to dashboard')
            return True
        except Exception as e:
            logger.error(f'Failed to publish report to dashboard: {str(e)}')
            return False
    
    def generate_and_distribute(self, output_path: str, report_level: str = 'basic', 
                               distribution_config: Optional[Dict[str, Any]] = None) -> Dict[str, bool]:
        """
        生成报告并根据配置进行分发
        
        Args:
            output_path: 输出文件路径
            report_level: 报告级别
            distribution_config: 分发配置
        
        Returns:
            Dict[str, bool]: 各分发渠道的结果状态
        """
        # 生成报告
        report_generated = self.generate_html_report(output_path, report_level)
        
        results = {'report_generated': report_generated}
        
        if not report_generated:
            logger.error('Failed to generate report, skipping distribution')
            return results
        
        if not distribution_config:
            logger.info('No distribution config provided, report generated but not distributed')
            return results
        
        # 发送邮件
        if 'email' in distribution_config:
            email_config = distribution_config['email']
            email_result = self.send_report_by_email(
                recipients=email_config.get('recipients', []),
                smtp_config=email_config.get('smtp', {}),
                report_path=output_path
            )
            results['email_sent'] = email_result
        
        # 发布到仪表盘
        if 'dashboard' in distribution_config:
            dashboard_result = self.publish_to_dashboard(distribution_config['dashboard'])
            results['dashboard_published'] = dashboard_result
        
        return results


def generate_report(scan_results: Dict[str, Any], target_url: str, output_path: str,
                   format: str = 'text', report_level: str = 'basic', language: str = 'zh-CN',
                   distribution_config: Optional[Dict[str, Any]] = None) -> Tuple[str, Dict[str, bool]]:
    """
    生成安全扫描报告，并可选择自动分发
    
    Args:
        scan_results: 扫描结果
        target_url: 目标URL
        output_path: 输出文件路径
        format: 报告格式 (text, json, html)
        report_level: 报告级别 ("basic", "standard", "comprehensive")
        language: 报告语言 ('zh-CN', 'en-US'等)
        distribution_config: 分发配置，包含邮件和仪表盘等分发渠道的配置
        
    Returns:
        Tuple[str, Dict[str, bool]]: 报告文件路径和各分发渠道的结果状态
    """
    # 确保输出目录存在
    os.makedirs(os.path.dirname(os.path.abspath(output_path)), exist_ok=True)
    
    # 初始化ReportGenerator
    generator = ReportGenerator(scan_results, target_url, language)
    
    # 根据格式生成报告
    if format == 'html':
        # 使用ReportGenerator类生成HTML报告
        generator.generate_html_report(output_path, report_level)
    elif format == 'json':
        # 生成JSON格式报告
        # 根据报告级别过滤结果
        filtered_results = generator._filter_results_by_level(scan_results, report_level)
        
        report_data = {
            'target_url': target_url,
            'scan_time': datetime.now().isoformat(),
            'report_level': report_level,
            'report_level_description': generator._get_report_level_description(report_level),
            'results': filtered_results,
            'language': language
        }
        
        with open(output_path, 'w', encoding='utf-8') as f:
            json.dump(report_data, f, ensure_ascii=False, indent=2)
    else:
        # 生成文本格式报告
        # 根据报告级别过滤结果
        filtered_results = generator._filter_results_by_level(scan_results, report_level)
        
        with open(output_path, 'w', encoding='utf-8') as f:
            translations = generator.translations[language]
            f.write(f"{translations['report_title']}\n")
            f.write(f"=" * 50 + "\n")
            f.write(f"{translations['target']}: {target_url}\n")
            f.write(f"{translations['scan_time']}: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
            f.write(f"{translations['report_level']}: {generator._get_report_level_description(report_level)}\n")
            f.write(f"=" * 50 + "\n\n")
            
            # 统计漏洞数量
            total_vulnerabilities = 0
            vulnerability_summary = {}
            
            for module, results in filtered_results.items():
                if module == 'scan_metadata':
                    continue
                
                if isinstance(results, dict):
                    if 'error' in results:
                        f.write(f"[{module}] {translations['error']}: {results['error']}\n\n")
                    elif 'vulnerabilities' in results:
                        count = len(results['vulnerabilities'])
                        vulnerability_summary[module] = count
                        total_vulnerabilities += count
                        
                        f.write(f"[{module}] {translations['total_vulnerabilities']}: {count}\n")
                        
                        # 只在全面检测级别显示详细漏洞信息
                        if report_level == "comprehensive" and count > 0:
                            for vuln in results['vulnerabilities']:
                                severity = vuln.get('severity', 'unknown')
                                severity_text = translations.get(severity, severity)
                                title = vuln.get('title', translations['unknown'])
                                f.write(f"  - [{severity_text}] {title}\n")
                                if 'description' in vuln:
                                    f.write(f"    {translations['description']}: {vuln['description'][:100]}...\n")
                        f.write("\n")
                    else:
                        f.write(f"[{module}] {translations['no_vulnerabilities']}\n\n")
                
            # 添加总结
            f.write(f"{translations['scan_summary']}\n")
            f.write(f"=" * 50 + "\n")
            f.write(f"{translations['total_vulnerabilities']}: {total_vulnerabilities}\n")
            f.write(f"{translations['total_modules']}: {len(filtered_results) - (1 if 'scan_metadata' in filtered_results else 0)}\n")
            
            if total_vulnerabilities > 0:
                f.write(f"\n{translations['vulnerability_distribution']}:\n")
                for module, count in vulnerability_summary.items():
                    if count > 0:
                        f.write(f"  - {module}: {count}\n")
            
            # 只在全面检测级别添加修复建议摘要
            if report_level == "comprehensive":
                f.write(f"\n{translations['recommendation_summary']}:\n")
                f.write(f"=" * 50 + "\n")
                has_recommendations = False
                
                for module, results in filtered_results.items():
                    if isinstance(results, dict) and 'vulnerabilities' in results:
                        for vuln in results['vulnerabilities']:
                            if 'recommendation' in vuln:
                                has_recommendations = True
                                severity = vuln.get('severity', 'unknown')
                                severity_text = translations.get(severity, severity)
                                title = vuln.get('title', translations['unknown'])
                                f.write(f"[{severity_text}] {title}\n")
                                f.write(f"{translations['recommendation']}: {vuln['recommendation']}\n\n")
                
                if not has_recommendations:
                    f.write(f"{translations['no_recommendations']}\n")
    
    # 处理分发
    distribution_results = {'report_generated': True}
    if distribution_config and format == 'html':
        distribution_results = generator.generate_and_distribute(output_path, report_level, distribution_config)
    
    return output_path, distribution_results
import os
import sys
import importlib
import time
from typing import Dict, Any, List, Optional, Set
import logging
import numpy as np
import json
import threading

# 尝试导入连锁分析器
try:
    from modules.chain_analysis.chain_analysis import analyze_chains
    CHAIN_ANALYSIS_AVAILABLE = True
except ImportError:
    CHAIN_ANALYSIS_AVAILABLE = False
    logging.warning('连锁分析模块加载失败，将使用传统扫描模式')

# 尝试导入漏洞预测器
try:
    from models.vulnerability_predictor import VulnerabilityPredictor
    VULNERABILITY_PREDICTOR_AVAILABLE = True
except ImportError:
    VULNERABILITY_PREDICTOR_AVAILABLE = False
    logging.warning('漏洞预测器模块加载失败，将使用传统扫描模式')

# 添加项目根目录到Python路径
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

class SecurityScanner:
    """网站安全扫描器核心类
    
    负责协调和运行各种安全检测模块，收集扫描结果
    支持资产发现、漏洞检测、专项深度检测、结果降噪和优先级算法等功能
    """
    
    def __init__(self, target_url: str, config: Optional[Dict] = None):
        """
        初始化安全扫描器
        
        Args:
            target_url: 目标网站URL
            config: 配置参数
        """
        self.target_url = target_url
        self.config = config or {}
        self.modules = []
        self.results = {}
        self.timeout = self.config.get('timeout', 300)
        self.verbose = self.config.get('verbose', False)
        self.vulnerability_predictor = None
        self.scan_history = []
        self.thread_limit = self.config.get('scan_threads', 5)
        self.active_scan_enabled = self.config.get('active_scan', {}).get('enabled', True)
        self.passive_scan_enabled = self.config.get('passive_scan', {}).get('enabled', True)
        self.ai_enhanced_enabled = self.config.get('ai_enhanced', {}).get('enabled', True)
        self.rate_limit = self.config.get('rate_limit', 10)
        self.max_concurrent_requests = self.config.get('max_concurrent_requests', 20)
        
        # 初始化日志
        logging.basicConfig(level=logging.INFO if self.verbose else logging.WARNING,
                           format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
        self.logger = logging.getLogger('SecurityScanner')
        
        # 加载漏洞预测模型
        if self.ai_enhanced_enabled:
            self._load_vulnerability_predictor()
        
        # 加载历史扫描数据
        self._load_scan_history()
        
    def load_modules(self, module_names: Optional[List[str]] = None):
        """
        加载安全检测模块
        
        Args:
            module_names: 指定要加载的模块列表，如果为None则加载所有模块
        """
        modules_dir = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), 'modules')
        
        # 如果指定了模块列表，则只加载这些模块
        if module_names:
            for module_name in module_names:
                module_path = os.path.join(modules_dir, module_name)
                if os.path.exists(module_path):
                    self.modules.append(module_name)
                    self.logger.info(f'加载模块: {module_name}')
                else:
                    self.logger.warning(f'模块不存在: {module_name}')
        else:
            # 加载所有模块
            for item in os.listdir(modules_dir):
                item_path = os.path.join(modules_dir, item)
                if os.path.isdir(item_path) and not item.startswith('__'):
                    self.modules.append(item)
            self.logger.info(f'加载了 {len(self.modules)} 个模块')
            
    def _perform_asset_discovery(self):
        """
        执行资产发现
        包括主动爬虫、子域爆破、端口扫描、CDN/WAF绕过等
        """
        try:
            # 尝试导入asset_discovery模块
            asset_module = importlib.import_module('modules.asset_discovery.asset_discovery')
            if hasattr(asset_module, 'AssetDiscovery'):
                asset_discovery = asset_module.AssetDiscovery(self.target_url, self.config)
                asset_results = asset_discovery.discover()
                self.results['asset_discovery'] = asset_results
                self.logger.info(f'资产发现完成，发现 {len(asset_results.get("subdomains", []))} 个子域名和 {len(asset_results.get("ports", []))} 个开放端口')
        except Exception as e:
            self.logger.error(f'资产发现模块执行失败: {str(e)}')
            
    def _execute_passive_scan(self):
        """
        执行被动扫描
        不向目标发送主动请求，通过分析已有信息获取安全信息
        """
        try:
            passive_results = {}
            
            # 遍历模块，执行那些支持被动扫描的模块
            for module_name in self.modules:
                try:
                    module = importlib.import_module(f'modules.{module_name}.{module_name}')
                    if hasattr(module, 'passive_scan'):
                        self.logger.info(f'执行被动扫描模块: {module_name}')
                        result = module.passive_scan(self.target_url, self.config)
                        passive_results[module_name] = result
                except Exception as e:
                    self.logger.error(f'被动扫描模块 {module_name} 执行失败: {str(e)}')
            
            self.results['passive_results'] = passive_results
            self.logger.info('被动扫描完成')
        except Exception as e:
            self.logger.error(f'被动扫描执行失败: {str(e)}')
    
    def scan_with_chain_detection(self, modules: Optional[List[str]] = None) -> Dict[str, Any]:
        """
        执行连锁性检测 - 模块间共享检测结果以提高检测效果
        
        Args:
            modules: 指定要运行的模块列表
            
        Returns:
            扫描结果字典
        """
        self.logger.info(f'开始连锁性检测，目标: {self.target_url}')
        start_time = time.time()
        
        # 加载模块
        self.load_modules(modules)
        
        # 检查并加载chain_analysis模块（如果可用且未包含在模块列表中）
        if CHAIN_ANALYSIS_AVAILABLE and 'chain_analysis' not in self.modules:
            self.modules.insert(0, 'chain_analysis')
            self.logger.info('已添加连锁分析模块到扫描队列')
        
        # 共享数据结构，用于模块间传递信息
        shared_context = {
            'target_url': self.target_url,
            'findings': {},  # 存储各模块的发现
            'vulnerabilities': [],  # 存储发现的漏洞
            'assets': {},  # 存储发现的资产信息
            'config': self.config,
            'chain_analyzer': None  # 预留连锁分析器位置
        }
        
        # 如果连锁分析器可用，优化模块执行顺序
        if CHAIN_ANALYSIS_AVAILABLE:
            analyzer = get_analyzer()
            shared_context['chain_analyzer'] = analyzer
            self.modules = analyzer.get_module_execution_order(self.modules)
            self.logger.info(f'连锁分析器已优化模块执行顺序')
        
        # 按顺序执行模块，实现连锁检测
        for module_name in self.modules:
            self.logger.info(f'运行连锁检测模块: {module_name}')
            try:
                # 准备模块扫描策略
                module_strategy = {
                    'priority_params': [],
                    'preferred_payloads': [],
                    'skip_checks': []
                }
                
                # 如果连锁分析器可用，调整扫描策略
                if CHAIN_ANALYSIS_AVAILABLE and shared_context.get('chain_analyzer'):
                    analyzer = shared_context['chain_analyzer']
                    module_strategy = analyzer.adjust_scanning_strategy(module_name, module_strategy)
                    self.logger.debug(f'为模块 {module_name} 调整策略: {module_strategy}')
                    shared_context['current_strategy'] = module_strategy
                
                # 尝试以不同方式导入模块
                module_result = self._run_module_with_context(module_name, shared_context)
                self.results[module_name] = module_result
                
                # 将结果添加到共享上下文
                if isinstance(module_result, dict):
                    # 添加发现到共享上下文
                    if 'findings' in module_result:
                        shared_context['findings'][module_name] = module_result['findings']
                    
                    # 添加漏洞到共享上下文
                    if 'vulnerabilities' in module_result:
                        shared_context['vulnerabilities'].extend(module_result['vulnerabilities'])
                        
                    # 添加资产信息到共享上下文
                    if 'assets' in module_result:
                        shared_context['assets'][module_name] = module_result['assets']
                    
                    # 如果连锁分析器可用，将结果注册到分析器
                    if CHAIN_ANALYSIS_AVAILABLE and shared_context.get('chain_analyzer'):
                        analyzer = shared_context['chain_analyzer']
                        # 注册模块发现的关键数据
                        if isinstance(module_result, dict):
                            if 'findings' in module_result:
                                analyzer.register_data(module_name, 'findings', module_result['findings'])
                            if 'vulnerabilities' in module_result:
                                analyzer.register_data(module_name, 'vulnerabilities', module_result['vulnerabilities'])
                            if 'assets' in module_result:
                                analyzer.register_data(module_name, 'assets', module_result['assets'])
                            # 注册特定模块类型的技术信息
                            if module_name == 'technology_detection' and 'technologies' in module_result:
                                analyzer.register_data(module_name, 'technologies', module_result['technologies'])
                
                # 检查是否超时
                if time.time() - start_time > self.timeout:
                    self.logger.warning(f'扫描超时，已扫描 {len(self.results)} 个模块')
                    break
                    
            except Exception as e:
                self.logger.error(f'模块 {module_name} 执行失败: {str(e)}')
                self.results[module_name] = {'error': str(e)}
        
        total_time = time.time() - start_time
        self.logger.info(f'连锁检测完成，耗时 {total_time:.2f} 秒')
        
        # 添加扫描元数据
        self.results['scan_metadata'] = {
            'target_url': self.target_url,
            'total_modules_scanned': len(self.results),
            'successful_modules': sum(1 for m in self.results.values() if not isinstance(m, dict) or 'error' not in m),
            'scan_duration_seconds': total_time,
            'timestamp': time.time(),
            'chain_detection': True
        }
        
        # 更新漏洞预测模型
        self._update_vulnerability_predictor()
        
        # 保存扫描历史
        self._save_scan_history()
        
        # 添加扫描时间信息
        self.results['scan_duration'] = total_time
        self.results['scan_timestamp'] = time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(start_time))
        
        return self.results
    
    def _load_vulnerability_predictor(self):
        """
        加载漏洞预测模型
        """
        if not VULNERABILITY_PREDICTOR_AVAILABLE:
            self.logger.warning('漏洞预测器模块不可用')
            self.vulnerability_predictor = None
            return
        
        try:
            model_path = self.config.get('model_path', os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), 'models', 'vulnerability_predictor.pkl'))
            config = {
                'model_type': self.config.get('model_type', 'random_forest'),
                'n_estimators': self.config.get('n_estimators', 100)
            }
            self.vulnerability_predictor = VulnerabilityPredictor(model_path=model_path, config=config)
            
            # 尝试加载已训练的模型
            if not self.vulnerability_predictor.load_model():
                self.logger.info('模型文件不存在，将在首次扫描后创建新模型')
                self.vulnerability_predictor.is_trained = False
            else:
                self.logger.info('漏洞预测模型加载成功')
        except Exception as e:
            self.logger.error(f'加载漏洞预测模型失败: {str(e)}')
            self.vulnerability_predictor = None
    
    def scan(self) -> Dict[str, Any]:
        """
        执行安全扫描
        
        Returns:
            扫描结果字典
        """
        start_time = time.time()
        self.logger.info(f'开始扫描目标: {self.target_url}')
        
        # 初始化结果字典
        self.results = {
            'target': self.target_url,
            'start_time': time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(start_time)),
            'modules_run': [],
            'vulnerabilities': {},
            'asset_discovery': {},
            'scan_duration': 0,
            'passive_results': {},
            'active_results': {},
            'chain_analysis': {},
            'priority_results': {},
            'regulatory_compliance': {}
        }
        
        try:
            # 加载扫描模块
            self._load_modules()
            
            # 执行资产发现
            self._perform_asset_discovery()
            
            # 执行被动扫描
            if self.passive_scan_enabled:
                self._execute_passive_scan()
            
            # 执行主动扫描
            if self.active_scan_enabled:
                if CHAIN_ANALYSIS_AVAILABLE:
                    self._execute_chain_analysis()
                else:
                    # 执行传统扫描
                    self._execute_traditional_scan()
            
            # 使用漏洞预测模型分析结果
            if self.vulnerability_predictor and self.ai_enhanced_enabled:
                self._predict_vulnerabilities()
                
            # 应用结果降噪与优先级算法
            self._apply_noise_reduction()
            self._apply_priority_algorithm()
            
            # 执行多法规基线检查
            self._perform_regulatory_compliance_check()
            
        except Exception as e:
            self.logger.error(f'扫描过程中发生错误: {str(e)}')
            self.results['error'] = str(e)
            
        finally:
            # 计算扫描时长
            self.results['scan_duration'] = time.time() - start_time
            self.logger.info(f'扫描完成，耗时: {self.results["scan_duration"]:.2f} 秒')
            
            # 保存扫描结果
            self._save_scan_history()
            
        return self.results
    
    def _predict_vulnerabilities(self) -> List[str]:
        """
        预测目标网站可能存在的漏洞类型
        
        Returns:
            预测的漏洞类型列表
        """
        if not self.vulnerability_predictor or not self.scan_history:
            return []
        
        try:
            # 提取目标网站特征
            features = self._extract_website_features()
            
            # 预测漏洞类型
            predictions = self.vulnerability_predictor.predict([features])
            
            # 将预测结果转换为漏洞类型
            vulnerability_types = []
            for module_name, is_vulnerable in zip(self.modules, predictions[0]):
                if is_vulnerable:
                    vulnerability_types.append(module_name)
            
            return vulnerability_types
        except Exception as e:
            self.logger.error(f'预测漏洞类型失败: {str(e)}')
            return []
    
    def _extract_website_features(self) -> List[float]:
        """
        提取目标网站特征
        
        Returns:
            特征向量
        """
        # 这里简化处理，实际应用中应提取更丰富的特征
        # 例如：网站技术栈、页面复杂度、URL结构、表单数量等
        features = []
        
        try:
            # 提取域名长度特征
            domain_length = len(self.target_url)
            features.append(domain_length)
            
            # 提取是否使用HTTPS
            uses_https = 1 if self.target_url.startswith('https://') else 0
            features.append(uses_https)
            
            # 填充到固定长度
            max_features = 10
            while len(features) < max_features:
                features.append(0)
            
        except Exception as e:
            self.logger.error(f'提取网站特征失败: {str(e)}')
            features = [0] * 10
        
        return features
    
    def _prioritize_modules(self, predicted_vulnerabilities: List[str]):
        """
        根据预测结果调整模块扫描顺序
        
        Args:
            predicted_vulnerabilities: 预测的漏洞类型列表
        """
        # 优先扫描预测为可能存在漏洞的模块
        prioritized_modules = []
        remaining_modules = []
        
        for module_name in self.modules:
            if module_name in predicted_vulnerabilities:
                prioritized_modules.append(module_name)
            else:
                remaining_modules.append(module_name)
        
        # 更新模块顺序
        self.modules = prioritized_modules + remaining_modules
    
    def _update_vulnerability_predictor(self):
        """
        更新漏洞预测模型
        """
        try:
            # 准备训练数据
            X = []
            y = []
            
            # 添加当前扫描结果
            features = self._extract_website_features()
            X.append(features)
            
            # 构建标签向量
            labels = []
            for module_name in self.modules:
                # 检查该模块是否发现漏洞
                has_vulnerability = False
                if module_name in self.results:
                    module_result = self.results[module_name]
                    if isinstance(module_result, dict) and 'vulnerabilities' in module_result:
                        if len(module_result['vulnerabilities']) > 0:
                            has_vulnerability = True
                labels.append(1 if has_vulnerability else 0)
            y.append(labels)
            
            # 如果没有足够的历史数据，先保存当前结果
            if len(self.scan_history) < 5:
                self.logger.info('历史数据不足，无法更新预测模型')
                return
            
            # 从历史数据中提取训练样本
            for history in self.scan_history[-10:]:  # 只使用最近10次扫描记录
                X.append(history['features'])
                y.append(history['labels'])
            
            # 转换为numpy数组
            X = np.array(X)
            y = np.array(y)
            
            # 训练模型
            self.vulnerability_predictor = RandomForestClassifier(n_estimators=100, random_state=42)
            self.vulnerability_predictor.fit(X, y)
            
            # 评估模型
            X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)
            y_pred = self.vulnerability_predictor.predict(X_test)
            accuracy = accuracy_score(y_test, y_pred)
            self.logger.info(f'漏洞预测模型更新成功，准确率: {accuracy:.2f}')
            
            # 保存模型
            model_dir = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), 'models')
            os.makedirs(model_dir, exist_ok=True)
            model_path = os.path.join(model_dir, 'vulnerability_predictor.pkl')
            joblib.dump(self.vulnerability_predictor, model_path)
        except Exception as e:
            self.logger.error(f'更新漏洞预测模型失败: {str(e)}')
    
    def _load_scan_history(self):
        """
        加载历史扫描数据
        """
        history_path = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                                   'data', 'scan_history.json')
        
        try:
            if os.path.exists(history_path):
                with open(history_path, 'r', encoding='utf-8') as f:
                    self.scan_history = json.load(f)
                self.logger.info(f'加载了 {len(self.scan_history)} 条历史扫描记录')
        except Exception as e:
            self.logger.error(f'加载历史扫描数据失败: {str(e)}')
            self.scan_history = []
    
    def _save_scan_history(self):
        """
        保存当前扫描数据到历史记录
        """
        try:
            # 构建历史记录条目
            history_entry = {
                'url': self.target_url,
                'timestamp': time.time(),
                'features': self._extract_website_features(),
                'labels': []
            }
            
            # 添加标签
            for module_name in self.modules:
                has_vulnerability = False
                if module_name in self.results:
                    module_result = self.results[module_name]
                    if isinstance(module_result, dict) and 'vulnerabilities' in module_result:
                        if len(module_result['vulnerabilities']) > 0:
                            has_vulnerability = True
                history_entry['labels'].append(1 if has_vulnerability else 0)
            
            # 添加到历史记录
            self.scan_history.append(history_entry)
            
            # 只保留最近100条记录
            self.scan_history = self.scan_history[-100:]
            
            # 保存到文件
            data_dir = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), 'data')
            os.makedirs(data_dir, exist_ok=True)
            history_path = os.path.join(data_dir, 'scan_history.json')
            with open(history_path, 'w', encoding='utf-8') as f:
                json.dump(self.scan_history, f, indent=2, ensure_ascii=False)
        except Exception as e:
            self.logger.error(f'保存扫描历史失败: {str(e)}')
    
    def _run_module_with_context(self, module_name: str, shared_context: Dict[str, Any]) -> Dict[str, Any]:
        """
        运行单个扫描模块并传递共享上下文
        
        Args:
            module_name: 模块名称
            shared_context: 共享上下文数据
            
        Returns:
            模块扫描结果
        """
        # 尝试不同的模块导入模式
        try:
            # 方式1: 尝试直接导入主模块文件
            module_path = f'modules.{module_name}.{module_name}'
            module = importlib.import_module(module_path)
            
            # 查找模块中的扫描函数（支持带上下文的函数）
            if hasattr(module, 'scan_with_context'):
                return module.scan_with_context(shared_context)
            elif hasattr(module, 'scan'):
                return module.scan(self.target_url)
            elif hasattr(module, f'scan_{module_name}'):
                scan_func = getattr(module, f'scan_{module_name}')
                return scan_func(self.target_url)
            elif hasattr(module, f'check_{module_name}'):
                check_func = getattr(module, f'check_{module_name}')
                return check_func(self.target_url)
        except ImportError:
            # 方式2: 尝试从模块目录下的主要文件导入
            try:
                # 检查是否有main.py或scanner.py
                for main_file in ['main', 'scanner']:
                    try:
                        module_path = f'modules.{module_name}.{main_file}'
                        module = importlib.import_module(module_path)
                        if hasattr(module, 'scan_with_context'):
                            return module.scan_with_context(shared_context)
                        elif hasattr(module, 'scan'):
                            return module.scan(self.target_url)
                    except ImportError:
                        continue
            except Exception:
                pass
                
        # 如果所有导入方式都失败，返回基础扫描信息
        return {
            'module': module_name,
            'target': self.target_url,
            'scanned': True,
            'vulnerabilities': [],
            'notes': '模块扫描已执行，但未发现明确的扫描函数'
        }
    
    def _run_module(self, module_name: str) -> Dict[str, Any]:
        """
        运行单个扫描模块
        
        Args:
            module_name: 模块名称
            
        Returns:
            模块扫描结果
        """
        # 尝试不同的模块导入模式
        try:
            # 方式1: 尝试直接导入主模块文件
            module_path = f'modules.{module_name}.{module_name}'
            module = importlib.import_module(module_path)
            
            # 查找模块中的扫描函数
            if hasattr(module, 'scan'):
                return module.scan(self.target_url)
            elif hasattr(module, f'scan_{module_name}'):
                scan_func = getattr(module, f'scan_{module_name}')
                return scan_func(self.target_url)
            elif hasattr(module, f'check_{module_name}'):
                check_func = getattr(module, f'check_{module_name}')
                return check_func(self.target_url)
        except ImportError:
            # 方式2: 尝试从模块目录下的主要文件导入
            try:
                # 检查是否有main.py或scanner.py
                for main_file in ['main', 'scanner']:
                    try:
                        module_path = f'modules.{module_name}.{main_file}'
                        module = importlib.import_module(module_path)
                        if hasattr(module, 'scan'):
                            return module.scan(self.target_url)
                    except ImportError:
                        continue
            except Exception:
                pass
                
        # 如果所有导入方式都失败，返回基础扫描信息
        return {
            'module': module_name,
            'target': self.target_url,
            'scanned': True,
            'vulnerabilities': [],
            'notes': '模块扫描已执行，但未发现明确的扫描函数'
        }
    
    def get_summary(self) -> Dict[str, Any]:
        """
        获取扫描结果摘要
        
        Returns:
            扫描摘要
        """
        summary = {
            'target_url': self.target_url,
            'total_modules': len(self.modules),
            'scanned_modules': len(self.results),
            'vulnerability_count': 0,
            'vulnerabilities_by_severity': {
                'critical': 0,
                'high': 0,
                'medium': 0,
                'low': 0
            }
        }
        
        # 统计漏洞数量
        for module_name, result in self.results.items():
            if module_name == 'scan_metadata':
                continue
            
            if isinstance(result, dict) and 'vulnerabilities' in result:
                summary['vulnerability_count'] += len(result['vulnerabilities'])
                
                # 统计不同严重程度的漏洞
                for vuln in result['vulnerabilities']:
                    severity = vuln.get('severity', 'low').lower()
                    if severity in summary['vulnerabilities_by_severity']:
                        summary['vulnerabilities_by_severity'][severity] += 1
        
        return summary
    
    def scan_all(self) -> Dict[str, Any]:
        """
        扫描所有安全模块（兼容main.py中的调用）
        
        Returns:
            扫描结果字典
        """
        # 先加载所有模块
        self.load_modules()
        # 然后执行扫描
        return self.scan()
    
    def diff_analysis(self, previous_results: Dict[str, Any], current_results: Dict[str, Any]) -> Dict[str, Any]:
        """
        比较两次扫描结果的差异
        
        Args:
            previous_results: 之前的扫描结果
            current_results: 当前的扫描结果
            
        Returns:
            差异分析结果
        """
        diff_result = {
            'new_vulnerabilities': [],
            'fixed_vulnerabilities': [],
            'unchanged_vulnerabilities': [],
            'severity_changes': []
        }
        
        # 检查新增的漏洞
        for module_name, current_module_result in current_results.items():
            if module_name == 'scan_metadata' or 'error' in current_module_result:
                continue
                
            if 'vulnerabilities' in current_module_result:
                # 获取当前模块的漏洞
                current_vulnerabilities = current_module_result['vulnerabilities']
                
                # 获取之前模块的漏洞
                previous_vulnerabilities = []
                if module_name in previous_results and 'vulnerabilities' in previous_results[module_name]:
                    previous_vulnerabilities = previous_results[module_name]['vulnerabilities']
                
                # 检查新增漏洞
                for vuln in current_vulnerabilities:
                    # 简单比较，实际应用中应使用更复杂的匹配算法
                    is_new = True
                    for prev_vuln in previous_vulnerabilities:
                        if vuln.get('payload') == prev_vuln.get('payload') and \
                           vuln.get('parameter') == prev_vuln.get('parameter'):
                            is_new = False
                            break
                    
                    if is_new:
                        diff_result['new_vulnerabilities'].append({
                            'module': module_name,
                            'vulnerability': vuln
                        })
                    
                    # 检查严重性变化
                    for prev_vuln in previous_vulnerabilities:
                        if vuln.get('payload') == prev_vuln.get('payload') and \
                           vuln.get('parameter') == prev_vuln.get('parameter') and \
                           vuln.get('severity') != prev_vuln.get('severity'):
                            diff_result['severity_changes'].append({
                                'module': module_name,
                                'vulnerability': vuln,
                                'old_severity': prev_vuln.get('severity')
                            })
                            break
        
        # 检查已修复的漏洞
        for module_name, previous_module_result in previous_results.items():
            if module_name == 'scan_metadata' or 'error' in previous_module_result:
                continue
                
            if 'vulnerabilities' in previous_module_result:
                # 获取之前模块的漏洞
                previous_vulnerabilities = previous_module_result['vulnerabilities']
                
                # 获取当前模块的漏洞
                current_vulnerabilities = []
                if module_name in current_results and 'vulnerabilities' in current_results[module_name]:
                    current_vulnerabilities = current_results[module_name]['vulnerabilities']
                
                # 检查已修复漏洞
                for vuln in previous_vulnerabilities:
                    # 简单比较，实际应用中应使用更复杂的匹配算法
                    is_fixed = True
                    for curr_vuln in current_vulnerabilities:
                        if vuln.get('payload') == curr_vuln.get('payload') and \
                           vuln.get('parameter') == curr_vuln.get('parameter'):
                            is_fixed = False
                            break
                    
                    if is_fixed:
                        diff_result['fixed_vulnerabilities'].append({
                            'module': module_name,
                            'vulnerability': vuln
                        })
        
        # 检查未变化的漏洞
        for module_name, current_module_result in current_results.items():
            if module_name == 'scan_metadata' or 'error' in current_module_result:
                continue
                
            if 'vulnerabilities' in current_module_result:
                # 获取当前模块的漏洞
                current_vulnerabilities = current_module_result['vulnerabilities']
                
                # 获取之前模块的漏洞
                if module_name in previous_results and 'vulnerabilities' in previous_results[module_name]:
                    previous_vulnerabilities = previous_results[module_name]['vulnerabilities']
                    
                    # 检查未变化的漏洞
                    for vuln in current_vulnerabilities:
                        for prev_vuln in previous_vulnerabilities:
                            if vuln.get('payload') == prev_vuln.get('payload') and \
                               vuln.get('parameter') == prev_vuln.get('parameter') and \
                               vuln.get('severity') == prev_vuln.get('severity'):
                                diff_result['unchanged_vulnerabilities'].append({
                                    'module': module_name,
                                    'vulnerability': vuln
                                })
                                break
        
        return diff_result
    
    def generate_diff_report(self, diff_results: Dict[str, Any]) -> str:
        """
        生成差异报告
        
        Args:
            diff_results: 差异分析结果
            
        Returns:
            差异报告字符串
        """
        report_lines = []
        report_lines.append("安全扫描差异报告")
        report_lines.append("=" * 50)
        
        # 新增漏洞
        if diff_results['new_vulnerabilities']:
            report_lines.append(f"新增漏洞: {len(diff_results['new_vulnerabilities'])}")
            for item in diff_results['new_vulnerabilities']:
                module = item['module']
                vuln = item['vulnerability']
                report_lines.append(f"  - [{module}] {vuln.get('description', '未知漏洞')}")
        else:
            report_lines.append("新增漏洞: 0")
        
        # 已修复漏洞
        if diff_results['fixed_vulnerabilities']:
            report_lines.append(f"已修复漏洞: {len(diff_results['fixed_vulnerabilities'])}")
            for item in diff_results['fixed_vulnerabilities']:
                module = item['module']
                vuln = item['vulnerability']
                report_lines.append(f"  - [{module}] {vuln.get('description', '未知漏洞')}")
        else:
            report_lines.append("已修复漏洞: 0")
        
        # 严重性变化
        if diff_results['severity_changes']:
            report_lines.append(f"严重性变化: {len(diff_results['severity_changes'])}")
            for item in diff_results['severity_changes']:
                module = item['module']
                vuln = item['vulnerability']
                old_severity = item['old_severity']
                report_lines.append(f"  - [{module}] {vuln.get('description', '未知漏洞')}: {old_severity} -> {vuln.get('severity')}")
        else:
            report_lines.append("严重性变化: 0")
        
        # 未变化漏洞
        if diff_results['unchanged_vulnerabilities']:
            report_lines.append(f"未变化漏洞: {len(diff_results['unchanged_vulnerabilities'])}")
        else:
            report_lines.append("未变化漏洞: 0")
        
        return "\n".join(report_lines)
    
    def _execute_chain_analysis(self):
        """
        执行连锁性检测
        支持模块间数据共享、策略调整和优先级处理
        """
        if not CHAIN_ANALYSIS_AVAILABLE:
            self.logger.warning('连锁分析模块不可用，将使用传统扫描模式')
            return
        
        try:
            # 准备共享上下文数据
            shared_context = {
                'target_url': self.target_url,
                'config': self.config,
                'asset_discovery': self.results.get('asset_discovery', {}),
                'discovered_modules': self.modules,
                'current_results': self.results
            }
            
            # 执行连锁分析
            chain_results = analyze_chains(shared_context)
            
            # 保存连锁分析结果
            self.results['chain_analysis'] = chain_results
            
            # 合并漏洞结果
            if 'vulnerabilities' in chain_results:
                # 将连锁分析发现的漏洞添加到结果中
                if 'vulnerabilities' not in self.results:
                    self.results['vulnerabilities'] = {}
                
                # 合并漏洞信息
                for vuln_type, vulns in chain_results['vulnerabilities'].items():
                    if vuln_type not in self.results['vulnerabilities']:
                        self.results['vulnerabilities'][vuln_type] = []
                    self.results['vulnerabilities'][vuln_type].extend(vulns)
            
            # 如果连锁分析提供了扫描策略，更新模块顺序
            if 'scan_strategy' in chain_results and 'modules_order' in chain_results['scan_strategy']:
                self.modules = chain_results['scan_strategy']['modules_order']
                self.logger.info(f'基于连锁分析调整扫描顺序: {" -> ".join(self.modules)}')
                
            self.logger.info(f'连锁分析完成，发现 {sum(len(vulns) for vulns in chain_results.get("vulnerabilities", {}).values())} 个潜在漏洞链')
        except Exception as e:
            self.logger.error(f'连锁分析执行失败: {str(e)}')
            # 失败时回退到传统扫描
            self._execute_traditional_scan()
            
    def _execute_traditional_scan(self):
        """
        执行传统扫描
        按顺序执行各个扫描模块
        """
        try:
            # 遍历并执行所有模块
            active_results = {}
            
            for module_name in self.modules:
                self.logger.info(f'执行扫描模块: {module_name}')
                try:
                    # 尝试以不同方式导入模块
                    module_result = self._run_module(module_name)
                    active_results[module_name] = module_result
                    
                    # 合并漏洞结果
                    if isinstance(module_result, dict) and 'vulnerabilities' in module_result:
                        if module_name not in self.results['vulnerabilities']:
                            self.results['vulnerabilities'][module_name] = []
                        self.results['vulnerabilities'][module_name].extend(module_result['vulnerabilities'])
                except Exception as e:
                    self.logger.error(f'模块 {module_name} 执行失败: {str(e)}')
                    active_results[module_name] = {'error': str(e)}
            
            self.results['active_results'] = active_results
            self.logger.info('传统扫描完成')
        except Exception as e:
            self.logger.error(f'传统扫描执行失败: {str(e)}')
            
    def _run_module(self, module_name: str):
        """
        运行指定的扫描模块
        
        Args:
            module_name: 模块名称
            
        Returns:
            模块运行结果
        """
        try:
            # 尝试以不同方式导入模块
            module = importlib.import_module(f'modules.{module_name}.{module_name}')
            
            # 检查是否有主类
            if hasattr(module, 'run'):
                # 如果有run函数，直接调用
                return module.run(self.target_url, self.config)
            elif hasattr(module, f'{module_name}Scanner'):
                # 如果有Scanner类，创建实例并运行
                scanner_class = getattr(module, f'{module_name}Scanner')
                scanner = scanner_class(self.config)
                return scanner.scan(self.target_url)
            elif hasattr(module, f'{module_name}Detector'):
                # 如果有Detector类，创建实例并运行
                detector_class = getattr(module, f'{module_name}Detector')
                detector = detector_class(self.config)
                return detector.detect(self.target_url)
            else:
                # 尝试寻找主类
                main_classes = [attr for attr in dir(module) if not attr.startswith('__') and attr.isupper()]
                if main_classes:
                    # 假设第一个大写类是主类
                    main_class = getattr(module, main_classes[0])
                    instance = main_class(self.config)
                    if hasattr(instance, 'scan'):
                        return instance.scan(self.target_url)
                    elif hasattr(instance, 'detect'):
                        return instance.detect(self.target_url)
            
            # 如果以上都不适用，抛出异常
            raise ImportError(f'无法找到模块 {module_name} 的主入口')
        except Exception as e:
            self.logger.error(f'模块 {module_name} 导入失败: {str(e)}')
            raise
            
    def _run_module_with_context(self, module_name: str, shared_context: Dict[str, Any]):
        """
        运行指定的扫描模块并传递共享上下文
        
        Args:
            module_name: 模块名称
            shared_context: 共享上下文
            
        Returns:
            模块运行结果
        """
        try:
            # 先尝试使用传统方式运行模块
            module_result = self._run_module(module_name)
            
            # 如果模块支持上下文，尝试使用上下文增强
            module = importlib.import_module(f'modules.{module_name}.{module_name}')
            if hasattr(module, 'run_with_context'):
                enhanced_result = module.run_with_context(self.target_url, self.config, shared_context)
                return enhanced_result
            
            return module_result
        except Exception as e:
            self.logger.error(f'模块 {module_name} 执行失败: {str(e)}')
            return {'error': str(e)}
            
    def _apply_noise_reduction(self):
        """
        应用结果降噪算法
        去除误报，提高扫描准确性
        """
        try:
            vulnerabilities = self.results.get('vulnerabilities', {})
            if not vulnerabilities:
                return
            
            # 简单的降噪逻辑：移除置信度低于阈值的结果
            confidence_threshold = self.config.get('noise_reduction', {}).get('confidence_threshold', 0.7)
            
            # 保留的漏洞列表
            filtered_vulnerabilities = {}
            
            for vuln_type, vulns in vulnerabilities.items():
                if isinstance(vulns, list):
                    filtered_vulns = [v for v in vulns if v.get('confidence', 1.0) >= confidence_threshold]
                    if filtered_vulns:
                        filtered_vulnerabilities[vuln_type] = filtered_vulns
                
            # 更新结果
            original_count = sum(len(vulns) for vulns in vulnerabilities.values())
            filtered_count = sum(len(vulns) for vulns in filtered_vulnerabilities.values())
            
            self.results['vulnerabilities'] = filtered_vulnerabilities
            self.results['noise_reduction_stats'] = {
                'original_count': original_count,
                'filtered_count': filtered_count,
                'reduction_rate': (original_count - filtered_count) / original_count if original_count > 0 else 0
            }
            
            self.logger.info(f'结果降噪完成，从 {original_count} 个结果中过滤出 {filtered_count} 个高置信度漏洞')
        except Exception as e:
            self.logger.error(f'结果降噪过程中发生错误: {str(e)}')
            
    def _apply_priority_algorithm(self):
        """
        应用优先级算法
        对漏洞进行评分和排序
        """
        try:
            vulnerabilities = self.results.get('vulnerabilities', {})
            if not vulnerabilities:
                return
            
            priority_results = []
            
            # 计算每个漏洞的优先级分数
            for vuln_type, vulns in vulnerabilities.items():
                for vuln in vulns:
                    # 计算CVSS评分
                    cvss_score = vuln.get('cvss_score', 5.0)
                    
                    # 考虑可利用性、影响范围等因素
                    exploitability = vuln.get('exploitability', 1.0)
                    impact_scope = vuln.get('impact_scope', 1.0)
                    
                    # 综合优先级评分
                    priority_score = cvss_score * exploitability * impact_scope
                    
                    # 添加优先级信息
                    vuln['priority_score'] = priority_score
                    priority_results.append(vuln)
            
            # 按优先级排序
            priority_results.sort(key=lambda x: x['priority_score'], reverse=True)
            
            # 更新结果
            self.results['priority_results'] = priority_results
            self.logger.info(f'优先级排序完成，共 {len(priority_results)} 个漏洞按风险优先级排序')
        except Exception as e:
            self.logger.error(f'优先级算法执行失败: {str(e)}')
            
    def _perform_regulatory_compliance_check(self):
        """
        执行多法规基线检查
        检查目标网站是否符合等保2.0、GDPR、PCI-DSS、HIPAA等法规要求
        """
        try:
            # 尝试导入compliance模块
            compliance_module = importlib.import_module('modules.compliance.compliance')
            if hasattr(compliance_module, 'ComplianceChecker'):
                compliance_checker = compliance_module.ComplianceChecker(self.config)
                compliance_results = compliance_checker.check_compliance(self.target_url)
                self.results['regulatory_compliance'] = compliance_results
                self.logger.info('多法规基线检查完成')
        except Exception as e:
            self.logger.error(f'多法规基线检查模块执行失败: {str(e)}')
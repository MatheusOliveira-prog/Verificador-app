# Arquivo: main.py
import os
os.environ['KIVY_NO_ARGS'] = '1'
from kivy.app import App
from kivy.uix.boxlayout import BoxLayout
from kivy.lang import Builder
from kivy.clock import mainthread
from threading import Thread
import requests, hashlib, time, webbrowser
from urllib.parse import urlparse, parse_qs, quote_plus
from bs4 import BeautifulSoup

# --- COLOQUE SUAS CHAVES DE API AQUI ---
VT_API_KEY = "2a002bf45a4c2e70867701051091c42df8b0c9529d3cf6cd9009647a629413ae"
URLSCAN_API_KEY = "0198f827-d271-716d-993c-409598a5779a"
# ----------------------------------------

Builder.load_file('interface.kv')

class MainLayout(BoxLayout):
    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.store_name, self.product_name, self.urlscan_result_url = None, None, None

    def iniciar_analise(self):
        url = self.ids.url_input.text.strip()
        if not url:
            self.update_verdict("LINK VAZIO", "warning")
            self.ids.log_output.text = "ERRO: Por favor, cole um link para analisar."
            return
        self.limpar_tudo()
        self.ids.analisar_button.disabled = True; self.ids.analisar_button.text = "Analisando..."
        Thread(target=self.verificar_link, args=(url,)).start()

    @mainthread
    def update_verdict(self, text, level):
        from kivy.graphics import Color, Rectangle
        self.ids.verdict_label.text = text
        colors = {"danger": (0.9, 0.29, 0.23), "warning": (0.95, 0.6, 0.07), "success": (0.18, 0.8, 0.44), "default": (0.2, 0.2, 0.2)}
        self.ids.verdict_label.canvas.before.clear()
        with self.ids.verdict_label.canvas.before:
            Color(rgba=colors.get(level, colors["default"]) + (1,))
            self.verdict_rect = Rectangle(pos=self.ids.verdict_label.pos, size=self.ids.verdict_label.size)
        self.ids.verdict_label.bind(pos=self.update_verdict_rect, size=self.update_verdict_rect)

    def update_verdict_rect(self, instance, value):
        self.verdict_rect.pos = instance.pos
        self.verdict_rect.size = instance.size

    @mainthread
    def update_log(self, message, append=True):
        if append: self.ids.log_output.text += message + "\n"
        else: self.ids.log_output.text = message + "\n"

    @mainthread
    def habilitar_botoes(self):
        if self.store_name: self.ids.reputation_button.disabled = False
        if self.product_name: self.ids.price_button.disabled = False
        if self.urlscan_result_url: self.ids.urlscan_button.disabled = False
        self.ids.analisar_button.disabled = False; self.ids.analisar_button.text = "Analisar"

    def limpar_tudo(self):
        self.update_log("Pronto para investigar...", append=False)
        self.update_verdict("Aguardando Análise", "default")
        self.ids.reputation_button.disabled = True
        self.ids.price_button.disabled = True
        self.ids.urlscan_button.disabled = True

    def analisar_virustotal(self, url):
        self.update_log("Analisando no VirusTotal...")
        try:
            url_id = hashlib.sha256(url.encode()).hexdigest()
            vt_url = f'https://www.virustotal.com/api/v3/urls/{url_id}'
            headers = {'x-apikey': VT_API_KEY.strip()}
            response = requests.get(vt_url, headers=headers, timeout=20)
            if response.status_code == 200:
                results = response.json()['data']['attributes']['last_analysis_stats']
                m, s = results.get('malicious', 0), results.get('suspicious', 0)
                self.update_log(f"-> VT: {m} maliciosos, {s} suspeitos.")
                return m + s
            self.update_log("-> VT: Link nunca visto antes.")
            return 0
        except Exception: return 0

    def obter_resultado_urlscan(self, url):
        self.update_log("Submetendo ao URLScan.io...")
        try:
            headers = {'API-Key': URLSCAN_API_KEY.strip(), 'Content-Type':'application/json'}
            data = {"url": url, "visibility": "public"}
            response = requests.post('https://urlscan.io/api/v1/scan/', headers=headers, json=data, timeout=20)
            if response.status_code == 200 and 'result' in response.json():
                self.urlscan_result_url = response.json()['result']
                self.update_log("-> URLScan: Link da análise gerado.")
            else: self.update_log(f"-> URLScan: Erro.")
        except Exception: self.update_log(f"-> URLScan: Erro de conexão.")

    def extrair_ecommerce(self, url):
        self.update_log("Analisando conteúdo E-commerce...")
        try:
            domain = urlparse(url).hostname
            self.store_name = domain.split('.')[-2].capitalize()
            headers = {'User-Agent': 'Mozilla/5.0'}
            page = requests.get(url, headers=headers, timeout=10, verify=False)
            soup = BeautifulSoup(page.content, 'html.parser')
            if soup.find('title') and soup.find('title').string:
                self.product_name = soup.find('title').string.strip()
            self.update_log(f"-> Loja: {self.store_name} | Produto: {self.product_name[:30]}...")
        except Exception: self.update_log(f"-> E-commerce: Erro.")

    def verificar_link(self, original_url):
        self.update_log(f"Iniciando análise para: {original_url}", append=False)
        url = urlparse(original_url).query and parse_qs(urlparse(original_url).query).get('u', [original_url])[0] or original_url
        if url != original_url: self.update_log(f"Redirecionamento detectado! Destino: {url}")
        self.extrair_ecommerce(url)
        malicious_hits = self.analisar_virustotal(url)
        self.obter_resultado_urlscan(url)
        if malicious_hits > 1: self.update_verdict("PERIGOSO", "danger")
        elif malicious_hits > 0: self.update_verdict("SUSPEITO", "warning")
        else: self.update_verdict("BAIXO RISCO", "success")
        self.habilitar_botoes()

    def abrir_url(self, url_type):
        if url_type == 'reputation' and self.store_name: webbrowser.open(f"https://www.google.com/search?q={quote_plus(self.store_name + ' reclame aqui')}")
        elif url_type == 'price' and self.product_name: webbrowser.open(f"https://www.google.com/search?tbm=shop&q={quote_plus(self.product_name)}")
        elif url_type == 'urlscan' and self.urlscan_result_url: webbrowser.open(self.urlscan_result_url)

class VerificadorApp(App):
    def build(self):
        requests.packages.urllib3.disable_warnings()
        return MainLayout()

if __name__ == '__main__':
    VerificadorApp().run()

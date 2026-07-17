"""
Référence globale au scheduler APScheduler.
Initialisée dans main.py au démarrage de l'application.
Permet aux routers d'accéder au scheduler sans imports circulaires.
"""

scheduler = None  # BackgroundScheduler | None

"""Create a consistent SQLite backup, including committed WAL data."""
import sqlite3
from pathlib import Path
from datetime import datetime,timezone
from app import app
folder=Path(app.config['DATABASE']).parent/'backups';folder.mkdir(exist_ok=True)
target=folder/('survey-'+datetime.now(timezone.utc).strftime('%Y%m%d-%H%M%S-%f')+'.sqlite3')
with sqlite3.connect(app.config['DATABASE']) as source, sqlite3.connect(target) as destination:
    source.backup(destination)
target.chmod(0o600)
print('Database backup created:',target)

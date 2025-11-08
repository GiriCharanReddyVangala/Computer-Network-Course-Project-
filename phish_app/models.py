# models.py
from sqlalchemy import create_engine, Column, Integer, String, Text, DateTime
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker
import datetime

# --- Database setup ---
# You can change the DB name or use Postgres later
DATABASE_URL = "sqlite:///phish_training.db"

Base = declarative_base()

# --- Model definition ---
class TrainingSample(Base):
    __tablename__ = "training_samples"
    id = Column(Integer, primary_key=True)
    url = Column(Text)
    raw_email = Column(Text)
    headers = Column(Text)
    subject = Column(Text)
    body = Column(Text)
    label = Column(Integer)  # 1 = phishing, 0 = legitimate
    created_at = Column(DateTime, default=datetime.datetime.utcnow)
    source = Column(String(100), default="manual")

# --- Create database ---
engine = create_engine(DATABASE_URL, echo=False)
Base.metadata.create_all(engine)

SessionLocal = sessionmaker(bind=engine)

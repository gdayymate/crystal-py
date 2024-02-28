from sqlalchemy import Column, Integer, String, DateTime, ForeignKey, create_engine
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import relationship
from datetime import datetime

Base = declarative_base()

class Fruit(Base):
  __tablename__ = "fruits"

  id = Column(Integer, primary_key=True)
  timestamp = Column(DateTime, default=datetime.now())
  seed = Column(String)
  epoch = Column(Integer)
  referenced_stem_id = Column(Integer, ForeignKey("stems.id"))
  signature = Column(String)

class Stem(Base):
  __tablename__ = "stems"

  id = Column(Integer, primary_key=True)
  timestamp = Column(DateTime, default=datetime.now())
  data = Column(String)
  previous_hash = Column(String)
  difficulty = Column(Integer)
  nonce = Column(String)
  hash = Column(String)
  fruits = relationship("Fruit", backref="stem")

class Leaf(Base):
  __tablename__ = "leaves"

  id = Column(Integer, primary_key=True)
  timestamp = Column(DateTime, default=datetime.now())
  data = Column(String)
  referenced_fruits = Column(String)
  coinbase_transaction = Column(String)
  difficulty = Column(Integer)
  nonce = Column(String)
  hash = Column(String)

class Blockchain(Base):
  __tablename__ = "blockchain"

  id = Column(Integer, primary_key=True)
  stem_id = Column(Integer, ForeignKey("stems.id"), nullable=False)
  leaf_id = Column(Integer, ForeignKey("leaves.id"), nullable=True)
  stem = relationship("Stem", uselist=False, foreign_keys=[stem_id])
  leaf = relationship("Leaf", uselist=False, foreign_keys=[leaf_id])

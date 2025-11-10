"""
Database Schemas

Define your MongoDB collection schemas here using Pydantic models.
These schemas are used for data validation in your application.

Each Pydantic model represents a collection in your database.
Model name is converted to lowercase for the collection name:
- User -> "user" collection
- Product -> "product" collection
- BlogPost -> "blogs" collection
"""

from pydantic import BaseModel, Field
from typing import Optional, List
from datetime import datetime

class Poem(BaseModel):
    """
    Poems collection schema
    Collection name: "poem"
    """
    title: str = Field(..., description="Poem title")
    excerpt: str = Field(..., description="Short excerpt for preview")
    content: str = Field(..., description="Full poem text")
    coverImage: Optional[str] = Field(None, description="Cover image URL or path")
    tags: List[str] = Field(default_factory=list, description="Tags/Categories")
    isFeatured: bool = Field(False, description="Mark as featured")
    createdAt: Optional[datetime] = Field(default=None, description="Creation date")

class AdminAuth(BaseModel):
    username: str
    password: str

"""Pydantic schemas for tenant branding endpoints."""

from datetime import datetime
from enum import StrEnum

from pydantic import BaseModel, Field


class LogoMode(StrEnum):
    """Logo display mode for tenant navigation."""

    MANDALA = "mandala"
    CUSTOM = "custom"


class GroupAvatarStyle(StrEnum):
    """Avatar style for group icons."""

    MANDALA = "mandala"
    ACRONYM = "acronym"


class LogoSlot(StrEnum):
    """Logo variant slot."""

    LIGHT = "light"
    DARK = "dark"


class BrandingSettings(BaseModel):
    """Response schema for tenant branding settings (no binary data)."""

    logo_mode: LogoMode = Field(LogoMode.MANDALA, description="Current logo display mode")
    use_logo_as_favicon: bool = Field(False, description="Use custom logo as favicon")
    site_title: str | None = Field(None, description="Custom site title (NULL = WeftId)")
    show_title_in_nav: bool = Field(True, description="Show title in navigation bar")
    has_logo_light: bool = Field(False, description="Whether a light logo is uploaded")
    has_logo_dark: bool = Field(False, description="Whether a dark logo is uploaded")
    logo_light_mime: str | None = Field(None, description="MIME type of light logo")
    logo_dark_mime: str | None = Field(None, description="MIME type of dark logo")
    group_avatar_style: GroupAvatarStyle = Field(
        GroupAvatarStyle.MANDALA, description="Default avatar style for group icons"
    )
    updated_at: datetime | None = Field(None, description="Last update timestamp")


class BrandingSettingsUpdate(BaseModel):
    """Request schema for updating branding display settings."""

    logo_mode: LogoMode = Field(..., description="Logo display mode")
    use_logo_as_favicon: bool = Field(False, description="Use custom logo as favicon")
    site_title: str | None = Field(
        None, max_length=30, description="Custom site title (max 30 chars)"
    )
    show_title_in_nav: bool = Field(True, description="Show title in navigation bar")
    group_avatar_style: GroupAvatarStyle = Field(
        GroupAvatarStyle.MANDALA, description="Default avatar style for group icons"
    )


class MandalaRandomizeResponse(BaseModel):
    """Response schema for mandala randomization."""

    seed: str = Field(..., description="The random seed used to generate the mandala")
    light_svg: str = Field(..., description="SVG markup for light mode")
    dark_svg: str = Field(..., description="SVG markup for dark mode")


class MandalaSaveRequest(BaseModel):
    """Request schema for saving a mandala as the tenant logo."""

    seed: str = Field(..., min_length=1, max_length=100, description="Mandala seed to save")

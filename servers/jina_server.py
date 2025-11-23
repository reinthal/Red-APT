#!/usr/bin/env python3
"""
Jina AI MCP Server
Provides web intelligence capabilities through Jina.ai endpoints:
- Web search (s.jina.ai)
- Fact checking/grounding (g.jina.ai)
- URL reading/ranking (r.jina.ai)
- Content extraction with AI analysis
"""

import asyncio
import json
import os
import urllib.parse
from typing import Optional, List, Dict, Any
from pydantic import BaseModel

from mcp.server.fastmcp import FastMCP

# Check for test mode
TEST_MODE = os.getenv("MCP_TEST_MODE", "").lower() == "true"

# Initialize FastMCP server
mcp = FastMCP("jina-ai")


# ============================================================================
# Data Models
# ============================================================================

class WebContentExtractionModel(BaseModel):
    """Structured extraction from web content"""
    urls: List[str] = []
    important_facts: List[str] = []
    quantities: List[str] = []
    important_dates: List[str] = []
    important_people: List[str] = []
    important_places: List[str] = []
    important_organizations: List[str] = []
    important_events: List[str] = []
    important_documents: List[str] = []
    important_links: List[str] = []


# ============================================================================
# Jina AI Client
# ============================================================================

class JinaClient:
    """Client for interacting with Jina.ai endpoints"""

    def __init__(self, token: Optional[str] = None, openai_key: Optional[str] = None):
        """Initialize with Jina token and optional OpenAI key for extraction"""
        self.token = token or os.getenv("JINA_API_KEY")
        self.headers = {}
        if self.token:
            self.headers = {
                "Authorization": f"Bearer {self.token}",
                "Content-Type": "application/json"
            }

        # Initialize OpenAI client if available
        self.openai_client = None
        try:
            import openai
            openai_api_key = openai_key or os.getenv("OPENAI_API_KEY")
            if openai_api_key:
                self.openai_client = openai.AsyncClient(api_key=openai_api_key)
        except ImportError:
            pass

    async def _fetch(self, url: str) -> str:
        """Fetch URL content using aiohttp"""
        try:
            import aiohttp
            async with aiohttp.ClientSession() as session:
                async with session.get(url, headers=self.headers, timeout=30) as response:
                    return await response.text()
        except ImportError:
            # Fallback to urllib for basic functionality
            import urllib.request
            req = urllib.request.Request(url, headers=self.headers)
            with urllib.request.urlopen(req, timeout=30) as response:
                return response.read().decode('utf-8')

    async def search(self, query: str) -> Dict[str, Any]:
        """
        Search using s.jina.ai endpoint
        Args:
            query: Search term
        Returns:
            API response as dict
        """
        encoded_query = urllib.parse.quote(query)
        url = f"https://s.jina.ai/{encoded_query}"
        response_text = await self._fetch(url)
        return {"results": response_text, "query": query}

    async def fact_check(self, query: str) -> Dict[str, Any]:
        """
        Get grounding info using g.jina.ai endpoint
        Args:
            query: Query to ground/fact-check
        Returns:
            API response as dict
        """
        encoded_query = urllib.parse.quote(query)
        url = f"https://g.jina.ai/{encoded_query}"
        response_text = await self._fetch(url)
        return {"results": response_text, "query": query}

    async def read_url(self, url: str) -> Dict[str, Any]:
        """
        Read/extract content from URL using r.jina.ai endpoint
        Args:
            url: URL to read
        Returns:
            API response as dict
        """
        encoded_url = urllib.parse.quote(url, safe='')
        read_url = f"https://r.jina.ai/{encoded_url}"
        response_text = await self._fetch(read_url)
        return {"results": response_text, "url": url}

    async def extract_content(self, text: str) -> Dict[str, Any]:
        """
        Extract structured information from text using OpenAI
        Args:
            text: Text to analyze
        Returns:
            Dict with structured extraction or error
        """
        if not self.openai_client:
            return {"error": "OpenAI client not available for content extraction"}

        try:
            response = await self.openai_client.chat.completions.create(
                model="gpt-4o",
                messages=[
                    {
                        "role": "system",
                        "content": """Extract structured information from the text. Return JSON with these fields:
- urls: List of URLs found
- important_facts: Key facts and statements
- quantities: Numbers, measurements, statistics
- important_dates: Dates and time references
- important_people: Names of people mentioned
- important_places: Locations and places
- important_organizations: Companies, organizations, institutions
- important_events: Events mentioned
- important_documents: Documents, reports, papers referenced
- important_links: Related links and references"""
                    },
                    {
                        "role": "user",
                        "content": text
                    }
                ],
                response_format={"type": "json_object"}
            )
            content = response.choices[0].message.content
            return {"status": "success", "extraction": json.loads(content)}
        except Exception as e:
            return {"status": "error", "error": str(e)}


# Global client instance
_jina_client: Optional[JinaClient] = None


def get_jina_client() -> JinaClient:
    """Get or create Jina client instance"""
    global _jina_client
    if _jina_client is None:
        _jina_client = JinaClient()
    return _jina_client


# ============================================================================
# Test Mode Responses
# ============================================================================

def get_test_search_results(query: str) -> Dict[str, Any]:
    """Generate test search results"""
    return {
        "query": query,
        "results": f"""# Search Results for: {query}

## Result 1: Example Security Article
**URL:** https://example.com/security/{query.replace(' ', '-')}
A comprehensive overview of {query} in the context of cybersecurity.
Key points: vulnerability assessment, risk mitigation, best practices.

## Result 2: Technical Documentation
**URL:** https://docs.example.com/{query.replace(' ', '-')}
Technical documentation covering {query} implementation and configuration.

## Result 3: Research Paper
**URL:** https://research.example.edu/papers/{query.replace(' ', '-')}.pdf
Academic research on {query} with detailed analysis and findings.

---
*Results retrieved via Jina AI Search (TEST MODE)*
""",
        "test_mode": True
    }


def get_test_fact_check_results(query: str) -> Dict[str, Any]:
    """Generate test fact-check results"""
    return {
        "query": query,
        "results": f"""# Fact Check: {query}

## Verification Status: PARTIALLY VERIFIED

### Claims Analysis:
1. **Primary Claim:** "{query}"
   - Confidence: 75%
   - Sources: 3 found

### Supporting Evidence:
- Source 1: https://example.com/facts - Supports claim
- Source 2: https://wiki.example.org - Partially supports
- Source 3: https://research.example.edu - Additional context

### Context:
This fact-check was performed using Jina AI's grounding service.
Multiple sources were analyzed to verify the claim.

---
*Fact-checked via Jina AI Grounding (TEST MODE)*
""",
        "test_mode": True
    }


def get_test_read_results(url: str) -> Dict[str, Any]:
    """Generate test URL read results"""
    return {
        "url": url,
        "results": f"""# Content from: {url}

## Page Title: Example Security Resource

### Main Content:
This is a simulated extraction of web content from {url}.

### Key Information:
- **Category:** Security Resources
- **Last Updated:** 2024-01-15
- **Author:** Security Team

### Summary:
This page contains information relevant to security research and
penetration testing. Key topics include vulnerability assessment,
network reconnaissance, and security best practices.

### Extracted Data:
- IP Addresses: 192.168.1.1, 10.0.0.1
- Domains: example.com, security.example.org
- Technologies: Apache 2.4, PHP 8.1, MySQL 8.0

---
*Content extracted via Jina AI Reader (TEST MODE)*
""",
        "test_mode": True
    }


def get_test_extraction_results(text: str) -> Dict[str, Any]:
    """Generate test extraction results"""
    return {
        "status": "success",
        "extraction": {
            "urls": ["https://example.com", "https://docs.example.com"],
            "important_facts": [
                "Security assessment completed",
                "Multiple vulnerabilities identified",
                "Remediation recommendations provided"
            ],
            "quantities": ["3 critical vulnerabilities", "15 medium issues", "99.9% uptime"],
            "important_dates": ["2024-01-15", "Q1 2024"],
            "important_people": ["John Smith (Security Lead)", "Jane Doe (CTO)"],
            "important_places": ["US-East-1", "EU-West-2"],
            "important_organizations": ["ACME Corp", "Security Inc"],
            "important_events": ["Security Audit 2024", "Compliance Review"],
            "important_documents": ["Security Assessment Report", "Risk Matrix"],
            "important_links": ["CVE-2024-1234", "OWASP Top 10"]
        },
        "test_mode": True
    }


# ============================================================================
# MCP Tools
# ============================================================================

@mcp.tool()
async def jina_search(query: str) -> str:
    """
    Search the web using Jina AI's search endpoint.

    Args:
        query: Search query string

    Returns:
        Search results as markdown-formatted text
    """
    if TEST_MODE:
        result = get_test_search_results(query)
        return json.dumps(result, indent=2)

    try:
        client = get_jina_client()
        result = await client.search(query)
        return json.dumps(result, indent=2)
    except Exception as e:
        return json.dumps({"error": str(e), "query": query})


@mcp.tool()
async def jina_fact_check(statement: str) -> str:
    """
    Fact-check a statement using Jina AI's grounding endpoint.

    Args:
        statement: Statement or claim to verify

    Returns:
        Fact-check results with source verification
    """
    if TEST_MODE:
        result = get_test_fact_check_results(statement)
        return json.dumps(result, indent=2)

    try:
        client = get_jina_client()
        result = await client.fact_check(statement)
        return json.dumps(result, indent=2)
    except Exception as e:
        return json.dumps({"error": str(e), "statement": statement})


@mcp.tool()
async def jina_read_url(url: str) -> str:
    """
    Read and extract content from a URL using Jina AI's reader endpoint.

    Args:
        url: URL to read and extract content from

    Returns:
        Extracted content as markdown-formatted text
    """
    if TEST_MODE:
        result = get_test_read_results(url)
        return json.dumps(result, indent=2)

    try:
        client = get_jina_client()
        result = await client.read_url(url)
        return json.dumps(result, indent=2)
    except Exception as e:
        return json.dumps({"error": str(e), "url": url})


@mcp.tool()
async def jina_extract_content(text: str) -> str:
    """
    Extract structured information from text using AI analysis.
    Requires OPENAI_API_KEY environment variable.

    Args:
        text: Text to analyze and extract information from

    Returns:
        Structured extraction with URLs, facts, dates, people, etc.
    """
    if TEST_MODE:
        result = get_test_extraction_results(text)
        return json.dumps(result, indent=2)

    try:
        client = get_jina_client()
        result = await client.extract_content(text)
        return json.dumps(result, indent=2)
    except Exception as e:
        return json.dumps({"error": str(e)})


@mcp.tool()
async def jina_search_and_extract(query: str) -> str:
    """
    Search the web and automatically extract structured information from results.
    Combines jina_search with jina_extract_content.

    Args:
        query: Search query string

    Returns:
        Search results with structured extraction
    """
    if TEST_MODE:
        search_result = get_test_search_results(query)
        extraction_result = get_test_extraction_results(search_result["results"])
        return json.dumps({
            "search": search_result,
            "extraction": extraction_result.get("extraction", {}),
            "test_mode": True
        }, indent=2)

    try:
        client = get_jina_client()

        # Search first
        search_result = await client.search(query)

        # Extract structured info from results
        extraction_result = await client.extract_content(search_result.get("results", ""))

        return json.dumps({
            "search": search_result,
            "extraction": extraction_result.get("extraction", {})
        }, indent=2)
    except Exception as e:
        return json.dumps({"error": str(e), "query": query})


@mcp.tool()
async def jina_read_and_extract(url: str) -> str:
    """
    Read a URL and automatically extract structured information.
    Combines jina_read_url with jina_extract_content.

    Args:
        url: URL to read and analyze

    Returns:
        URL content with structured extraction
    """
    if TEST_MODE:
        read_result = get_test_read_results(url)
        extraction_result = get_test_extraction_results(read_result["results"])
        return json.dumps({
            "content": read_result,
            "extraction": extraction_result.get("extraction", {}),
            "test_mode": True
        }, indent=2)

    try:
        client = get_jina_client()

        # Read URL first
        read_result = await client.read_url(url)

        # Extract structured info from content
        extraction_result = await client.extract_content(read_result.get("results", ""))

        return json.dumps({
            "content": read_result,
            "extraction": extraction_result.get("extraction", {})
        }, indent=2)
    except Exception as e:
        return json.dumps({"error": str(e), "url": url})


@mcp.tool()
async def jina_multi_search(queries: str) -> str:
    """
    Perform multiple searches in parallel.

    Args:
        queries: Comma-separated list of search queries

    Returns:
        Combined results from all searches
    """
    query_list = [q.strip() for q in queries.split(",") if q.strip()]

    if TEST_MODE:
        results = {}
        for query in query_list:
            results[query] = get_test_search_results(query)
        return json.dumps({"results": results, "test_mode": True}, indent=2)

    try:
        client = get_jina_client()
        tasks = [client.search(query) for query in query_list]
        search_results = await asyncio.gather(*tasks, return_exceptions=True)

        results = {}
        for query, result in zip(query_list, search_results):
            if isinstance(result, Exception):
                results[query] = {"error": str(result)}
            else:
                results[query] = result

        return json.dumps({"results": results}, indent=2)
    except Exception as e:
        return json.dumps({"error": str(e), "queries": query_list})


@mcp.tool()
async def jina_multi_read(urls: str) -> str:
    """
    Read multiple URLs in parallel.

    Args:
        urls: Comma-separated list of URLs to read

    Returns:
        Combined content from all URLs
    """
    url_list = [u.strip() for u in urls.split(",") if u.strip()]

    if TEST_MODE:
        results = {}
        for url in url_list:
            results[url] = get_test_read_results(url)
        return json.dumps({"results": results, "test_mode": True}, indent=2)

    try:
        client = get_jina_client()
        tasks = [client.read_url(url) for url in url_list]
        read_results = await asyncio.gather(*tasks, return_exceptions=True)

        results = {}
        for url, result in zip(url_list, read_results):
            if isinstance(result, Exception):
                results[url] = {"error": str(result)}
            else:
                results[url] = result

        return json.dumps({"results": results}, indent=2)
    except Exception as e:
        return json.dumps({"error": str(e), "urls": url_list})


@mcp.tool()
async def jina_osint_search(target: str, search_type: str = "all") -> str:
    """
    Perform OSINT-focused searches on a target.

    Args:
        target: Target to research (domain, company, person, etc.)
        search_type: Type of search - all, security, social, corporate

    Returns:
        OSINT-relevant search results
    """
    search_queries = {
        "security": [
            f"{target} vulnerability",
            f"{target} CVE",
            f"{target} security breach",
            f"{target} data leak"
        ],
        "social": [
            f"{target} linkedin",
            f"{target} twitter",
            f"{target} github",
            f"{target} social media"
        ],
        "corporate": [
            f"{target} employees",
            f"{target} company info",
            f"{target} press release",
            f"{target} technology stack"
        ],
        "all": [
            f"{target} security vulnerability",
            f"{target} technology stack",
            f"{target} employees linkedin",
            f"{target} github repositories"
        ]
    }

    queries = search_queries.get(search_type, search_queries["all"])

    if TEST_MODE:
        results = {}
        for query in queries:
            results[query] = get_test_search_results(query)
        return json.dumps({
            "target": target,
            "search_type": search_type,
            "results": results,
            "test_mode": True
        }, indent=2)

    try:
        client = get_jina_client()
        tasks = [client.search(query) for query in queries]
        search_results = await asyncio.gather(*tasks, return_exceptions=True)

        results = {}
        for query, result in zip(queries, search_results):
            if isinstance(result, Exception):
                results[query] = {"error": str(result)}
            else:
                results[query] = result

        return json.dumps({
            "target": target,
            "search_type": search_type,
            "results": results
        }, indent=2)
    except Exception as e:
        return json.dumps({"error": str(e), "target": target})


@mcp.tool()
async def jina_check_api_status() -> str:
    """
    Check Jina AI API status and configuration.

    Returns:
        API status and available features
    """
    client = get_jina_client()

    status = {
        "jina_api_key_configured": bool(client.token),
        "openai_client_available": client.openai_client is not None,
        "test_mode": TEST_MODE,
        "endpoints": {
            "search": "https://s.jina.ai/",
            "grounding": "https://g.jina.ai/",
            "reader": "https://r.jina.ai/"
        },
        "features": {
            "search": True,
            "fact_check": True,
            "url_reading": True,
            "content_extraction": client.openai_client is not None
        },
        "note": "Set JINA_API_KEY for authenticated access. Set OPENAI_API_KEY for content extraction."
    }

    return json.dumps(status, indent=2)


# ============================================================================
# Entry Point
# ============================================================================

if __name__ == "__main__":
    mcp.run()

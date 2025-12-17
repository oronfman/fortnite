from fastapi import FastAPI
from fastapi.responses import PlainTextResponse
import aiohttp
import uvicorn
import ipaddress

app = FastAPI(title="IP Ranges API", description="Fetch IP ranges from ipdeny.com in PeerBlock format")


async def fetch_ip_ranges(country_code):
    """Fetch IP ranges from ipdeny.com for a given country code."""
    try:
        url = f"https://www.ipdeny.com/ipblocks/data/countries/{country_code.lower()}.zone"
        async with aiohttp.ClientSession() as session:
            async with session.get(url, timeout=aiohttp.ClientTimeout(total=30)) as response:
                if response.status == 200:
                    content = await response.text()
                    return [line.strip() for line in content.split('\n') if line.strip()]
                return []
    except Exception as e:
        print(f"Error fetching IP ranges for {country_code}: {e}")
        return []


@app.get("/ip-ranges/peerblock", response_class=PlainTextResponse)
async def get_ip_ranges_peerblock():
    """
    Returns IP ranges for UK and Germany in PeerBlock format.
    PeerBlock format: Label:IP_Start-IP_End (e.g., China Internet Center:1.2.4.0-1.2.4.255)
    """

    def cidr_to_range(cidr):
        try:
            net = ipaddress.ip_network(cidr)
            return f"{net[0]}-{net[-1]}"
        except Exception:
            # If parsing fails, return the original string
            return cidr

    countries = {"GB": "United Kingdom", "DE": "Germany"}

    result_lines = []

    for code, label in countries.items():
        ranges = await fetch_ip_ranges(code)
        for r in ranges:
            rng = cidr_to_range(r)
            result_lines.append(f"{label}:{rng}")

    return '\n'.join(result_lines)


if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=8000)

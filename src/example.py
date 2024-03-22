"""Example Server."""

__title__ = "Example Server"
__author__ = "CoolCat467"

from collections.abc import AsyncIterator
from os import path
from typing import Final

import trio
from hypercorn.config import Config
from hypercorn.trio import serve
from quart import Response
from quart.templating import stream_template
from quart_trio import QuartTrio

app: Final = QuartTrio(
    __name__,
    template_folder="templates",
)


async def send_error(
    page_title: str,
    error_body: str,
    return_link: str | None = None,
) -> AsyncIterator[str]:
    """Stream error page."""
    return await stream_template(
        "error_page.html.jinja",
        page_title=page_title,
        error_body=error_body,
        return_link=return_link,
    )


async def get_exception_page(code: int, name: str, desc: str) -> tuple[AsyncIterator[str], int]:
    """Return Response for exception."""
    resp_body = await send_error(
        page_title=f"{code} {name}",
        error_body=desc,
    )
    return (resp_body, code)


@app.get("/")
async def root_get() -> tuple[AsyncIterator[str], int]:
    """Main page GET request."""
    return await get_exception_page(404, "Page not found", "Requested content does not exist.")


async def run_async(
    root_dir: str,
    port: int,
) -> None:
    """Asynchronous Entry Point."""
    ip_addr = "0.0.0.0"

    try:
        # Add more information about the address
        location = f"{ip_addr}:{port}"

        config = {
            "bind": [location],
            "worker_class": "trio",
        }
        app.config["SERVER_NAME"] = location

        app.jinja_options = {
            "trim_blocks": True,
            "lstrip_blocks": True,
        }

        config_obj = Config.from_mapping(config)

        proto = "http"
        print(f"Serving on {proto}://{location}\n(CTRL + C to quit)")

        await serve(app, config_obj)
    except OSError:
        print(f"Cannot bind to IP address '{ip_addr}' port {port}")
        exit(1)
    except KeyboardInterrupt:
        print("Shutting down from keyboard interrupt")


def run() -> None:
    """Synchronous Entry Point."""
    root_dir = path.dirname(__file__)
    port = 6002

    trio.run(
        run_async,
        root_dir,
        port,
        restrict_keyboard_interrupt_to_checkpoints=True,
    )


def main() -> None:
    """Call run after setup."""
    print(f"{__title__}\nProgrammed by {__author__}.\n")
    run()


if __name__ == "__main__":
    main()

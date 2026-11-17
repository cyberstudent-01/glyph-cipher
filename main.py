"""Interactive terminal interface for glyph-cipher."""

from __future__ import annotations

import threading

import pyperclip
from rich.console import Console
from rich.panel import Panel
from rich.prompt import Confirm, Prompt

from cipher import GlyphCipherError, decrypt_credential, encrypt_credential


console = Console()


def copy_to_clipboard(value: str, label: str) -> bool:
    try:
        pyperclip.copy(value)
    except (pyperclip.PyperclipException, OSError) as exc:
        console.print(f"[yellow]Clipboard unavailable ({exc}).[/yellow]")
        return False
    console.print(f"[green]{label} copied to the clipboard.[/green]")
    return True


def clear_clipboard(expected: str) -> None:
    try:
        if pyperclip.paste() == expected:
            pyperclip.copy("")
            console.print("[dim]Clipboard cleared.[/dim]")
    except (pyperclip.PyperclipException, OSError):
        pass


def prompt_passphrase(confirm: bool = False) -> str:
    while True:
        passphrase = Prompt.ask("Master Passphrase", password=True)
        if not confirm or passphrase == Prompt.ask("Confirm Passphrase", password=True):
            return passphrase
        console.print("[red]Passphrases do not match. Try again.[/red]")


def run() -> None:
    console.clear()
    console.print(Panel.fit("[bold cyan]GLYPH-CIPHER[/bold cyan]\n[dim]Offline credential translator[/dim]"))
    passphrase = prompt_passphrase(confirm=True)

    while True:
        console.print("\n[bold cyan]1[/bold cyan] Encode Credential")
        console.print("[bold cyan]2[/bold cyan] Decode Glyphs")
        console.print("[bold cyan]3[/bold cyan] Change Master Passphrase")
        console.print("[bold cyan]4[/bold cyan] Exit")
        choice = Prompt.ask("Select an operation", choices=["1", "2", "3", "4"], default="1")

        if choice == "1":
            credential = Prompt.ask("Credential", password=not Confirm.ask("Show credential while typing?", default=False))
            glyphs = encrypt_credential(credential, passphrase)
            console.print(Panel(glyphs, title="Encrypted Glyphs", border_style="cyan"))
            if Confirm.ask("Copy glyphs to clipboard?", default=True):
                copy_to_clipboard(glyphs, "Glyphs")
        elif choice == "2":
            glyphs = Prompt.ask("Glyph string")
            try:
                credential = decrypt_credential(glyphs, passphrase)
            except GlyphCipherError as exc:
                console.print(f"[red]{exc}[/red]")
                continue
            console.print("[green]Credential decrypted successfully.[/green]")
            if Confirm.ask("Print decrypted credential on screen?", default=False):
                console.print(Panel(credential, title="Decrypted Credential", border_style="green"))
            if copy_to_clipboard(credential, "Credential"):
                clipboard_timer = threading.Timer(15.0, clear_clipboard, args=(credential,))
                clipboard_timer.daemon = True
                clipboard_timer.start()
                console.print("[dim]Clipboard will be cleared in 15 seconds if unchanged.[/dim]")
        elif choice == "3":
            passphrase = prompt_passphrase(confirm=True)
            console.print("[green]Master passphrase updated for this session.[/green]")
        else:
            console.clear()
            return


if __name__ == "__main__":
    try:
        run()
    except KeyboardInterrupt:
        console.print("\n[yellow]Exiting.[/yellow]")

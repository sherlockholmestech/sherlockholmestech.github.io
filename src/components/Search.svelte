<script lang="ts">
import I18nKey from "@i18n/i18nKey";
import { i18n } from "@i18n/translation";
import Icon from "@iconify/svelte";
import { url } from "@utils/url-utils.ts";
import { onMount, tick } from "svelte";
import type { SearchResult } from "@/global";

let keyword = "";
let result: SearchResult[] = [];
let isSearching = false;
let pagefindLoaded = false;
let initialized = false;
let loadFailed = false;
let open = false;
let selectedIndex = 0;
let inputElement: HTMLInputElement;
let dialogElement: HTMLDialogElement;
let searchTimeout: ReturnType<typeof setTimeout> | undefined;
let searchToken = 0;

const resultLimit = 8;
const pagefindScriptUrl = url("/pagefind/pagefind.js");
const pagefindBasePath = url("/pagefind/");
const pagefindBaseUrl = url("/");

const fakeResult: SearchResult[] = [
	{
		url: url("/"),
		meta: {
			title: "This Is a Fake Search Result",
		},
		excerpt:
			"Because the search cannot work in the <mark>dev</mark> environment.",
	},
	{
		url: url("/"),
		meta: {
			title: "If You Want to Test the Search",
		},
		excerpt: "Try running <mark>pnpm build && pnpm preview</mark> instead.",
	},
];

const openPalette = async (): Promise<void> => {
	open = true;
	await tick();
	if (!dialogElement.open) {
		dialogElement.showModal();
	}
	inputElement?.focus();
	void ensurePagefind();
};

const closePalette = (): void => {
	open = false;
	selectedIndex = 0;
	if (dialogElement?.open) {
		dialogElement.close();
	}
};

const runSearch = async (query: string): Promise<void> => {
	const trimmedQuery = query.trim();
	const currentToken = ++searchToken;

	if (!trimmedQuery) {
		result = [];
		selectedIndex = 0;
		isSearching = false;
		return;
	}

	if (!initialized) {
		await ensurePagefind();
	}

	if (!initialized || loadFailed) {
		return;
	}

	isSearching = true;

	try {
		let searchResults: SearchResult[] = [];

		if (import.meta.env.PROD && pagefindLoaded && window.pagefind) {
			const response = await window.pagefind.search(trimmedQuery);
			searchResults = await Promise.all(
				response.results.slice(0, resultLimit).map((item) => item.data()),
			);
		} else if (import.meta.env.DEV) {
			searchResults = fakeResult;
		} else {
			console.error("Pagefind is not available in production environment.");
			return;
		}

		if (currentToken !== searchToken) {
			return;
		}

		result = searchResults;
		selectedIndex = 0;
	} catch (error) {
		if (currentToken === searchToken) {
			console.error("Search error:", error);
			result = [];
			selectedIndex = 0;
		}
	} finally {
		if (currentToken === searchToken) {
			isSearching = false;
		}
	}
};

const ensurePagefind = async (): Promise<void> => {
	if (initialized || import.meta.env.DEV) {
		return;
	}

	try {
		const pagefind = await import(/* @vite-ignore */ pagefindScriptUrl);
		await pagefind.options?.({
			basePath: pagefindBasePath,
			baseUrl: pagefindBaseUrl,
			excerptLength: 30,
		});
		await pagefind.init?.();

		window.pagefind = pagefind;
		pagefindLoaded = typeof pagefind.search === "function";
		initialized = true;
		loadFailed = !pagefindLoaded;

		if (keyword) {
			void runSearch(keyword);
		}
	} catch (error) {
		console.error("Failed to load Pagefind:", error);
		initialized = true;
		pagefindLoaded = false;
		loadFailed = true;
	}
};

const scheduleSearch = (query: string): void => {
	if (searchTimeout) {
		clearTimeout(searchTimeout);
	}

	searchTimeout = setTimeout(() => {
		void runSearch(query);
	}, 120);
};

const openSelectedResult = (): void => {
	const selectedResult = result[selectedIndex];
	if (!selectedResult) {
		return;
	}

	window.location.href = selectedResult.url;
	closePalette();
};

const handlePaletteKeydown = (event: KeyboardEvent): void => {
	if (event.key === "Escape") {
		event.preventDefault();
		closePalette();
		return;
	}

	if (event.key === "ArrowDown") {
		event.preventDefault();
		selectedIndex = Math.min(selectedIndex + 1, result.length - 1);
		return;
	}

	if (event.key === "ArrowUp") {
		event.preventDefault();
		selectedIndex = Math.max(selectedIndex - 1, 0);
		return;
	}

	if (event.key === "Enter") {
		event.preventDefault();
		openSelectedResult();
	}
};

const handleDialogClick = (event: MouseEvent): void => {
	if (event.target === dialogElement) {
		closePalette();
	}
};

onMount(() => {
	const initializeSearch = () => {
		initialized = true;
		pagefindLoaded =
			typeof window !== "undefined" &&
			!!window.pagefind &&
			typeof window.pagefind.search === "function";

		if (keyword) {
			void runSearch(keyword);
		}
	};

	const handleDocumentKeydown = (event: KeyboardEvent): void => {
		if ((event.metaKey || event.ctrlKey) && event.key.toLowerCase() === "k") {
			event.preventDefault();
			void openPalette();
		}
	};

	document.addEventListener("keydown", handleDocumentKeydown);

	if (import.meta.env.DEV) {
		initializeSearch();
	} else {
		void ensurePagefind();
	}

	return () => {
		document.removeEventListener("keydown", handleDocumentKeydown);
		if (searchTimeout) {
			clearTimeout(searchTimeout);
		}
	};
});

$: if (initialized && !loadFailed) {
	scheduleSearch(keyword);
}
</script>

<button
	on:click={openPalette}
	aria-label={i18n(I18nKey.search)}
	id="search-switch"
	class="btn-plain scale-animation rounded-lg h-11 w-11 lg:w-auto lg:px-4 active:scale-90"
>
	<Icon icon="material-symbols:search" class="text-[1.25rem] lg:mr-2"></Icon>
	<span class="hidden lg:inline text-sm font-medium">{i18n(I18nKey.search)}</span>
</button>

<dialog
	bind:this={dialogElement}
	id="search-panel"
	class="search-panel w-[calc(100vw-2rem)] max-w-2xl overflow-hidden rounded-2xl bg-[var(--float-panel-bg)] p-0 text-left text-inherit shadow-2xl transition backdrop:bg-black/40 dark:backdrop:bg-black/60"
	aria-label={i18n(I18nKey.search)}
	on:click={handleDialogClick}
	on:cancel={(event) => {
		event.preventDefault();
		closePalette();
	}}
	on:keydown={handlePaletteKeydown}
>
	<div
		class="overflow-hidden rounded-2xl bg-[var(--float-panel-bg)]"
		role="document"
	>
		<div class="flex h-14 items-center border-b border-[var(--line-divider)] px-4">
			<Icon icon="material-symbols:search" class="mr-3 text-[1.35rem] text-30"></Icon>
			<input
				bind:this={inputElement}
				bind:value={keyword}
				placeholder={i18n(I18nKey.search)}
				class="h-full min-w-0 flex-1 bg-transparent text-base text-90 outline-0 placeholder:text-black/30 dark:placeholder:text-white/30"
			/>
			<button
				type="button"
				aria-label="Close"
				class="btn-plain ml-3 h-9 w-9 rounded-lg active:scale-90"
				on:click={closePalette}
			>
				<Icon icon="material-symbols:close-rounded" class="text-[1.2rem]"></Icon>
			</button>
		</div>

		<div class="max-h-[min(30rem,calc(76vh-3.5rem))] overflow-y-auto p-2">
			{#if keyword.trim() && loadFailed}
				<div class="px-3 py-8 text-center text-sm text-50">Search failed to load</div>
			{:else if keyword.trim() && (!initialized || isSearching)}
				<div class="px-3 py-8 text-center text-sm text-50">Searching...</div>
			{:else if keyword.trim() && result.length === 0}
				<div class="px-3 py-8 text-center text-sm text-50">No results</div>
			{:else if !keyword.trim()}
				<div class="px-3 py-8 text-center text-sm text-50">Start typing to search posts</div>
			{:else}
				{#each result as item, index}
					<a
						href={item.url}
						class={`group block rounded-xl px-4 py-3 transition hover:bg-[var(--btn-plain-bg-hover)] active:bg-[var(--btn-plain-bg-active)] ${
							index === selectedIndex ? "bg-[var(--btn-plain-bg-hover)]" : ""
						}`}
						on:mouseenter={() => (selectedIndex = index)}
						on:click={closePalette}
					>
						<div class="flex items-center justify-between gap-3">
							<div class="min-w-0 truncate font-bold text-90 transition group-hover:text-[var(--primary)]">
								{item.meta.title}
							</div>
							<Icon icon="fa6-solid:chevron-right" class="shrink-0 text-[0.75rem] text-[var(--primary)]"></Icon>
						</div>
						<div class="mt-1 line-clamp-2 text-sm text-50">
							{@html item.excerpt}
						</div>
					</a>
				{/each}
			{/if}
		</div>
	</div>
</dialog>

<style>
	input:focus {
		outline: 0;
	}

	.search-panel {
		border: 0;
		margin-top: 12vh;
	}

	.search-panel::backdrop {
		backdrop-filter: blur(8px);
	}

	.search-panel mark {
		background: transparent;
		color: var(--primary);
		font-weight: 700;
	}
</style>

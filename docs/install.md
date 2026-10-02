<!-- SPDX-FileCopyrightText: 2026 Aleksandr Linde -->
<!-- SPDX-License-Identifier: Apache-2.0 -->

<!--
The site's Install section. The README keeps the one-line npm form so it stays
scannable on npm and GitHub; the site has room for every package manager, so
the build swaps this fragment in. Heading level and title must match the
README's Install heading for the swap to find it.
-->

## Install

npm:

```sh
npm i @rinsadev/core
```

pnpm:

```sh
pnpm add @rinsadev/core
```

yarn:

```sh
yarn add @rinsadev/core
```

bun:

```sh
bun add @rinsadev/core
```

Deno (npm specifier):

```js
import { compilePolicy, profiles } from 'npm:@rinsadev/core';
```

CDN (ESM, no install):

```js
import { compilePolicy, profiles } from 'https://esm.sh/@rinsadev/core';
```

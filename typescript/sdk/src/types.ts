import { ethers } from 'ethers';

import { types } from '@abacus-network/utils';

/**
 * RPC Pagination information for Polygon
 */
export interface Pagination {
  blocks: number;
  from: number;
}

/**
 * Enumeration of Abacus supported chains
 */
export enum Chains {
  alfajores,
  mumbai,
  kovan,
  goerli,
  fuji,
  rinkarby,
  rinkeby,
  ropsten,
  celo,
  ethereum,
  avalanche,
  polygon,
  test1,
  test2,
  test3,
}
export type ChainName = keyof typeof Chains;
export type ChainMap<Value> = Record<ChainName, Value>;
export type ChainSubsetMap<Networks extends ChainName, Value> = Record<
  Networks,
  Value
>;
export type Remotes<
  Networks extends ChainName,
  Local extends Networks,
> = Exclude<Networks, Local>;
export type RemoteChainSubsetMap<
  Networks extends ChainName,
  Local extends Networks,
  Value,
> = Record<Remotes<Networks, Local>, Value>;

/**
 * The names of Abacus supported chains
 */
const ALL_MAINNET_NAMES = ['celo', 'ethereum', 'avalanche', 'polygon'] as const;

const ALL_TESTNET_NAMES = [
  'alfajores',
  'mumbai',
  'kovan',
  'goerli',
  'fuji',
  'rinkarby',
  'rinkeby',
  'ropsten',
] as const;

const ALL_TEST_NAMES = ['test1', 'test2', 'test3'] as const;

export const ALL_CHAIN_NAMES = [
  ...ALL_MAINNET_NAMES,
  ...ALL_TESTNET_NAMES,
  ...ALL_TEST_NAMES,
];

/**
 * A Domain (and its characteristics)
 */
export interface Domain {
  id: number;
  name: ChainName;
  nativeTokenDecimals?: number;
  paginate?: Pagination;
}

export type Connection = ethers.providers.Provider | ethers.Signer;

export type ProxiedAddress = {
  proxy: types.Address;
  implementation: types.Address;
  beacon: types.Address;
};

export type NameOrDomain = ChainName | number;
export type GeoResult = {
  ip: string;
  addressKind: string;
  status: 'located' | 'partial' | 'not-found' | 'non-public' | 'database-unavailable' | 'lookup-error';
  country: string | null;
  countryCode: string | null;
  region: string | null;
  city: string | null;
  latitude: number | null;
  longitude: number | null;
  accuracyRadiusKm: number | null;
  asn: number | null;
  organization: string | null;
};

export type GeoOrigin = {
  mode: 'manual' | 'public-ip';
  latitude: number;
  longitude: number;
  label: string;
  ip: string | null;
  accuracyRadiusKm: number | null;
};

export type GeoSnapshot = { origin: GeoOrigin | null; endpoints: GeoResult[] };

export type GeoFile = {
  fileName: string;
  state: 'ready' | 'invalid' | 'missing';
  databaseType: string | null;
  warning: string | null;
};

export type GeoSettings = {
  databases: { directory: string; city: GeoFile; asn: GeoFile };
  configuration: { mode: 'manual' | 'public-ip'; latitude: number | null; longitude: number | null; label: string | null; ip: string | null } | null;
  origin: GeoOrigin | null;
};

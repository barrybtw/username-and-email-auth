type DB = {
  users: { username: string; passwordHash: string; salt: string }[];
  sessions: {
    id: number;
    username: string;
    expires: number;
    created: number;
  }[];
};

export const DB = {
  users: [],
  sessions: [],
} as DB;

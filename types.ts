
export enum ContainerStatus {
  IDLE = 'IDLE',
  BUILDING = 'BUILDING',
  BUILD_SUCCESS = 'BUILD_SUCCESS',
  RUNNING = 'RUNNING',
  ERROR = 'ERROR',
}

export enum LogType {
  SYSTEM = 'SYSTEM',
  INPUT = 'INPUT',
  OUTPUT = 'OUTPUT',
  ERROR = 'ERROR',
  SUCCESS = 'SUCCESS',
}

export interface LogEntry {
  type: LogType;
  content: string;
  timestamp: string;
}

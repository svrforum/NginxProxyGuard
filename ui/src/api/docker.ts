import { apiGet } from './client'

export interface DockerContainerNetwork {
  name: string
  ip_address: string
}

export interface DockerContainerPort {
  container_port: number
  protocol: string
}

export interface DockerContainerInfo {
  name: string
  image: string
  state: string
  networks: DockerContainerNetwork[]
  ports: DockerContainerPort[]
}

export async function fetchDockerContainers(): Promise<DockerContainerInfo[]> {
  return apiGet<DockerContainerInfo[]>('/api/v1/docker/containers')
}

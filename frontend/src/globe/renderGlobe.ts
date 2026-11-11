import {
  AdditiveBlending, BufferGeometry, ConeGeometry, Group, Mesh, MeshBasicMaterial,
  PerspectiveCamera, Quaternion, Raycaster, Scene, ShaderMaterial, SphereGeometry, Spherical,
  SRGBColorSpace, Texture, TextureLoader, TubeGeometry, Vector2, Vector3, WebGLRenderer, Curve, MathUtils,
} from 'three';
import { OrbitControls } from 'three/addons/controls/OrbitControls.js';
import { directionColors } from './demoRoutes';
import type { Location, VisibleFlow } from './demoRoutes';

const radius = 1;
const up = new Vector3(0, 1, 0);

function position({ lat, lng }: Location) {
  const latitude = MathUtils.degToRad(lat);
  const longitude = MathUtils.degToRad(lng);
  return new Vector3(
    Math.cos(latitude) * Math.cos(longitude),
    Math.sin(latitude),
    -Math.cos(latitude) * Math.sin(longitude),
  );
}

class RouteCurve extends Curve<Vector3> {
  private readonly rotation: Quaternion;
  private readonly interpolation = new Quaternion();

  constructor(private readonly start: Vector3, end: Vector3, private readonly height: number) {
    super();
    this.rotation = new Quaternion().setFromUnitVectors(start, end);
  }

  override getPoint(t: number, target = new Vector3()) {
    const rotation = this.interpolation.identity().slerp(this.rotation, t);
    return target.copy(this.start).applyQuaternion(rotation)
      .multiplyScalar(radius + 0.014 + Math.sin(t * Math.PI) * this.height);
  }
}

function disposeMeshes(group: Group) {
  group.traverse(node => {
    if (node instanceof Mesh) {
      (node.geometry as BufferGeometry).dispose();
      node.material.dispose();
    }
  });
  group.clear();
}

export function renderGlobe(
  host: HTMLDivElement,
  select: (ip: string) => void,
  reportError: (message: string) => void,
) {
  const renderer = new WebGLRenderer({ antialias: true, alpha: true });
  renderer.setPixelRatio(Math.min(window.devicePixelRatio, 1.75));
  const canvas = renderer.domElement;
  canvas.setAttribute('aria-hidden', 'true');
  host.appendChild(canvas);

  const scene = new Scene();
  const camera = new PerspectiveCamera(37, 1, 0.05, 20);
  const controls = new OrbitControls(camera, canvas);
  controls.enablePan = false;
  controls.enableDamping = true;
  controls.minDistance = 1.45;
  controls.maxDistance = 6;
  controls.autoRotateSpeed = 0.45;

  const planet = new Group();
  const routes = new Group();
  scene.add(planet, routes);
  const ocean = new MeshBasicMaterial({ color: '#172f4c' });
  const earth = new Mesh(new SphereGeometry(radius, 72, 48), ocean);
  planet.add(earth);
  let disposed = false;
  let dirty = true;
  let texture: Texture | undefined;
  new TextureLoader().load(`${import.meta.env.BASE_URL}globe-countries.svg`, loaded => {
    if (disposed) { loaded.dispose(); return; }
    texture = loaded;
    texture.colorSpace = SRGBColorSpace;
    texture.anisotropy = Math.min(8, renderer.capabilities.getMaxAnisotropy());
    ocean.color.set('#ffffff');
    ocean.map = texture;
    ocean.needsUpdate = true;
    dirty = true;
  }, undefined, () => {
    if (!disposed) reportError('The globe border texture could not load.');
  });

  const atmosphere = new Mesh(new SphereGeometry(1.011, 64, 40), new ShaderMaterial({
    transparent: true, depthWrite: false, blending: AdditiveBlending,
    vertexShader: `
      varying vec3 normalView;
      varying vec3 viewDirection;
      void main() {
        vec4 point = modelViewMatrix * vec4(position, 1.0);
        normalView = normalMatrix * normal;
        viewDirection = -point.xyz;
        gl_Position = projectionMatrix * point;
      }`,
    fragmentShader: `
      varying vec3 normalView;
      varying vec3 viewDirection;
      void main() {
        float rim = pow(1.0 - max(dot(normalize(normalView), normalize(viewDirection)), 0.0), 3.2);
        gl_FragColor = vec4(0.18, 0.48, 0.95, rim * 0.65);
      }`,
  }));
  planet.add(atmosphere);

  const raycaster = new Raycaster();
  const pointer = new Vector2();
  const pickable: Mesh[] = [];
  const particles: { mesh: Mesh; curve: RouteCurve; offset: number }[] = [];
  const down = new Vector2();
  const targetCamera = new Vector3();
  let focusing = false;
  let paused = false;
  let autoRotate = false;
  let speed = 1;
  let phase = 0;
  let previousTime: number | undefined;
  let routeSignature = '';
  let originPoint: Location | null = null;

  function focus(direction: Vector3, distance = camera.position.length()) {
    targetCamera.copy(direction).normalize().multiplyScalar(distance);
    focusing = true;
  }

  function reset() {
    focus(position(originPoint ?? { lat: 26, lng: -19 }), 4.25);
  }

  reset();
  camera.position.copy(targetCamera);
  controls.update();
  focusing = false;

  const resize = new ResizeObserver(() => {
    if (!host.clientWidth || !host.clientHeight) return;
    camera.aspect = host.clientWidth / host.clientHeight;
    camera.fov = MathUtils.radToDeg(2 * Math.atan(Math.tan(MathUtils.degToRad(37 / 2)) / Math.min(1, camera.aspect)));
    camera.updateProjectionMatrix();
    renderer.setSize(host.clientWidth, host.clientHeight);
    dirty = true;
  });
  resize.observe(host);
  let visible = true;
  const intersection = new IntersectionObserver(([entry]) => {
    visible = entry.isIntersecting;
    previousTime = undefined;
    dirty = true;
  });
  intersection.observe(host);

  function cast(event: MouseEvent) {
    const rect = canvas.getBoundingClientRect();
    pointer.set((event.clientX - rect.left) / rect.width * 2 - 1, 1 - (event.clientY - rect.top) / rect.height * 2);
    raycaster.setFromCamera(pointer, camera);
    return raycaster.intersectObject(earth)[0];
  }

  function pointerDown(event: PointerEvent) {
    down.set(event.clientX, event.clientY);
    focusing = false;
  }

  function click(event: MouseEvent) {
    if (Math.hypot(event.clientX - down.x, event.clientY - down.y) > 5) return;
    const ground = cast(event);
    const hit = raycaster.intersectObjects(pickable)[0];
    if (hit && (!ground || hit.distance < ground.distance)) select(hit.object.userData.ip);
  }

  function doubleClick(event: MouseEvent) {
    const ground = cast(event);
    if (ground) focus(ground.point);
  }

  function contextLost(event: Event) {
    event.preventDefault();
    renderer.setAnimationLoop(null);
    reportError('The 3D graphics context was lost. Reopen the map to try again.');
  }

  canvas.addEventListener('pointerdown', pointerDown);
  canvas.addEventListener('click', click);
  canvas.addEventListener('dblclick', doubleClick);
  canvas.addEventListener('webglcontextlost', contextLost);
  controls.addEventListener('change', () => { dirty = true; });
  renderer.setAnimationLoop(time => {
    if (!visible || document.hidden) return;
    const dt = Math.min((time - (previousTime ?? time)) / 1000, 0.05);
    previousTime = time;
    if (focusing) {
      camera.position.lerp(targetCamera, 1 - Math.exp(-9 * dt));
      if (camera.position.distanceToSquared(targetCamera) < 0.00002) {
        camera.position.copy(targetCamera);
        focusing = false;
      }
    }
    controls.autoRotate = autoRotate && !focusing;
    controls.update(dt);
    const movingParticles = !paused && particles.length > 0;
    if (!dirty && !movingParticles) return;
    if (movingParticles) phase = (phase + dt * 0.31 * speed) % 1;
    for (const { curve, mesh, offset } of particles) {
      curve.getPoint((phase + offset) % 1, mesh.position);
    }
    renderer.render(scene, camera);
    dirty = false;
  });

  return {
    reset,
    rotate(horizontal: number, vertical: number) {
      const angle = new Spherical().setFromVector3(focusing ? targetCamera : camera.position);
      angle.theta += horizontal;
      angle.phi = MathUtils.clamp(angle.phi + vertical, 0.02, Math.PI - 0.02);
      focus(new Vector3().setFromSpherical(angle), angle.radius);
    },
    zoom(factor: number) { focus(camera.position, MathUtils.clamp(camera.position.length() * factor, 1.45, 6)); },
    focusOn(location: Location) { focus(position(location)); },
    setMotion(animate: boolean, rotate: boolean, rate: number) {
      paused = !animate;
      autoRotate = rotate;
      speed = rate;
    },
    setFlows(visible: VisibleFlow[], origin: Location | null, selected: string | undefined, lowDetail: boolean) {
      // Byte growth within one width band leaves the existing GPU geometry in place.
      const signature = JSON.stringify([origin?.lat, origin?.lng, selected, lowDetail, visible.map(({ flow, directions }) =>
        [flow.ip, flow.lat, flow.lng, flow.flagged, directions.map(direction => [direction, widthBand(flow[direction])])])]);
      if (signature === routeSignature) return;
      const changedOrigin = origin?.lat !== originPoint?.lat || origin?.lng !== originPoint?.lng;
      originPoint = origin;
      routeSignature = signature;
      if (changedOrigin && origin) reset();
      dirty = true;
      disposeMeshes(routes);
      pickable.length = 0;
      particles.length = 0;
      if (!origin) return;
      const local = position(origin);
      const station = new Mesh(new SphereGeometry(0.026, 12, 8), new MeshBasicMaterial({ color: '#e1f4ff' }));
      station.position.copy(local).multiplyScalar(1.012);
      routes.add(station);
      for (const { flow, directions } of visible) {
        const remote = position(flow);
        const angle = local.angleTo(remote);
        const highlighted = selected === flow.ip;
        const marker = new Mesh(new SphereGeometry(highlighted ? 0.03 : 0.021, 12, 8),
          new MeshBasicMaterial({ color: flow.flagged ? '#ff637e' : '#a0ccff' }));
        marker.position.copy(remote).multiplyScalar(angle < 0.0001 ? 1.044 : 1.016);
        marker.userData.ip = flow.ip;
        routes.add(marker);
        pickable.push(marker);
        if (angle < 0.0001) continue;

        for (const direction of directions) {
          const inbound = direction === 'inbound';
          const height = MathUtils.clamp(angle * 0.27, 0.075, 0.41) + (inbound ? 0.06 : 0);
          const curve = new RouteCurve(inbound ? remote : local, inbound ? local : remote, height);
          const color = directionColors[direction];
          const width = (0.004 + widthBand(flow[direction]) * 0.0011) * (highlighted ? 1.45 : 1);
          const track = new Mesh(new TubeGeometry(curve, lowDetail ? 24 : 54, width, 6, false),
            new MeshBasicMaterial({ color, transparent: true, opacity: highlighted ? 0.88 : 0.47, depthWrite: false }));
          track.userData.ip = flow.ip;
          pickable.push(track);
          routes.add(track);

          const arrow = new Mesh(new ConeGeometry(0.023, 0.05, 8), new MeshBasicMaterial({ color }));
          curve.getPoint(0.53, arrow.position);
          arrow.quaternion.setFromUnitVectors(up, curve.getTangent(0.53));
          arrow.userData.ip = flow.ip;
          pickable.push(arrow);
          routes.add(arrow);

          const count = lowDetail ? 1 : 3;
          for (let index = 0; index < count; index++) {
            const mesh = new Mesh(new SphereGeometry(0.012, 8, 6), new MeshBasicMaterial({ color }));
            particles.push({ mesh, curve, offset: index / count + (inbound ? 0.14 : 0) });
            routes.add(mesh);
          }
        }
      }
    },
    dispose() {
      disposed = true;
      resize.disconnect();
      intersection.disconnect();
      renderer.setAnimationLoop(null);
      canvas.removeEventListener('pointerdown', pointerDown);
      canvas.removeEventListener('click', click);
      canvas.removeEventListener('dblclick', doubleClick);
      canvas.removeEventListener('webglcontextlost', contextLost);
      controls.dispose();
      texture?.dispose();
      disposeMeshes(planet);
      disposeMeshes(routes);
      renderer.dispose();
      renderer.forceContextLoss();
      canvas.remove();
    },
  };
}

function widthBand(bytes: number) {
  return Math.min(10, Math.floor(Math.log10(1 + bytes) * 2) / 2);
}

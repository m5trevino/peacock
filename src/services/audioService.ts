
class AudioService {
  private ctx: AudioContext | null = null;

  private init() {
    if (!this.ctx) {
      this.ctx = new (window.AudioContext || (window as any).webkitAudioContext)();
    }
  }

  playSuccess() {
    this.init();
    const osc = this.ctx!.createOscillator();
    const gain = this.ctx!.createGain();

    osc.type = 'sine';
    osc.frequency.setValueAtTime(880, this.ctx!.currentTime);
    osc.frequency.exponentialRampToValueAtTime(1320, this.ctx!.currentTime + 0.1);

    gain.gain.setValueAtTime(0.1, this.ctx!.currentTime);
    gain.gain.exponentialRampToValueAtTime(0.01, this.ctx!.currentTime + 0.4);

    osc.connect(gain);
    gain.connect(this.ctx!.destination);

    osc.start();
    osc.stop(this.ctx!.currentTime + 0.4);
  }

  playSymphony(index: number) {
    this.init();
    const now = this.ctx!.currentTime;

    // C Major Scale (DO-RE-MI-FA-SO-LA-TI-DO)
    const scale = [
      261.63, 293.66, 329.63, 349.23, 392.00, 440.00, 493.88, 523.25
    ];

    const noteIndex = index % scale.length;
    const freq = scale[noteIndex];
    const octaveShift = Math.floor(index / scale.length);
    const finalFreq = freq * Math.pow(2, octaveShift);

    const osc = this.ctx!.createOscillator();
    const gain = this.ctx!.createGain();

    osc.type = 'triangle';
    osc.frequency.setValueAtTime(finalFreq, now);

    gain.gain.setValueAtTime(0, now);
    gain.gain.linearRampToValueAtTime(0.1, now + 0.05);
    gain.gain.exponentialRampToValueAtTime(0.001, now + 0.8);

    osc.connect(gain);
    gain.connect(this.ctx!.destination);

    osc.start();
    osc.stop(now + 0.8);
  }

  playBriefcaseAhhh() {
    this.init();
    const now = this.ctx!.currentTime;

    // THE "AHHHHH" CHORD (Heavenly Choir Layer)
    const choirNotes = [261.63, 329.63, 392.00, 523.25]; // C Major Chord
    choirNotes.forEach(freq => {
      const osc = this.ctx!.createOscillator();
      const gain = this.ctx!.createGain();
      osc.type = 'sine';
      osc.frequency.setValueAtTime(freq, now);

      gain.gain.setValueAtTime(0, now);
      gain.gain.linearRampToValueAtTime(0.05, now + 0.2);
      gain.gain.exponentialRampToValueAtTime(0.001, now + 2);

      osc.connect(gain);
      gain.connect(this.ctx!.destination);
      osc.start(now);
      osc.stop(now + 2);
    });

    // THE MECHANICAL LOCK-IN (Industrial Latch Layer)
    const noise = this.ctx!.createBufferSource();
    const bufferSize = this.ctx!.sampleRate * .1;
    const buffer = this.ctx!.createBuffer(1, bufferSize, this.ctx!.sampleRate);
    const data = buffer.getChannelData(0);
    for (let i = 0; i < bufferSize; i++) data[i] = Math.random() * 2 - 1;
    noise.buffer = buffer;

    const filter = this.ctx!.createBiquadFilter();
    filter.type = 'lowpass';
    filter.frequency.setValueAtTime(1000, now);
    filter.frequency.exponentialRampToValueAtTime(100, now + 0.1);

    const noiseGain = this.ctx!.createGain();
    noiseGain.gain.setValueAtTime(0.2, now);
    noiseGain.gain.exponentialRampToValueAtTime(0.001, now + 0.1);

    noise.connect(filter);
    filter.connect(noiseGain);
    noiseGain.connect(this.ctx!.destination);
    noise.start(now);
  }

  playError() {
    this.init();
    const osc = this.ctx!.createOscillator();
    const gain = this.ctx!.createGain();

    osc.type = 'sawtooth';
    osc.frequency.setValueAtTime(110, this.ctx!.currentTime);
    osc.frequency.linearRampToValueAtTime(55, this.ctx!.currentTime + 0.3);

    gain.gain.setValueAtTime(0.1, this.ctx!.currentTime);
    gain.gain.linearRampToValueAtTime(0.01, this.ctx!.currentTime + 0.3);

    osc.connect(gain);
    gain.connect(this.ctx!.destination);

    osc.start();
    osc.stop(this.ctx!.currentTime + 0.3);
  }

  private humOsc: OscillatorNode | null = null;
  private humGain: GainNode | null = null;

  startHum() {
    this.init();
    if (this.humOsc) return;

    this.humOsc = this.ctx!.createOscillator();
    this.humGain = this.ctx!.createGain();

    this.humOsc.type = 'sine';
    this.humOsc.frequency.setValueAtTime(50, this.ctx!.currentTime); // Low hum

    this.humGain.gain.setValueAtTime(0, this.ctx!.currentTime);
    this.humGain.gain.linearRampToValueAtTime(0.02, this.ctx!.currentTime + 2); // Fade in

    this.humOsc.connect(this.humGain);
    this.humGain.connect(this.ctx!.destination);

    this.humOsc.start();
  }

  stopHum() {
    if (!this.humOsc || !this.humGain) return;

    const now = this.ctx!.currentTime;
    this.humGain.gain.cancelScheduledValues(now);
    this.humGain.gain.setValueAtTime(this.humGain.gain.value, now);
    this.humGain.gain.linearRampToValueAtTime(0, now + 0.5);

    this.humOsc.stop(now + 0.5);
    this.humOsc = null;
    this.humGain = null;
  }

  playJackpot() {
    this.init();
    const now = this.ctx!.currentTime;

    const notes = [
      { f: 523.25, t: 0 },    // C5
      { f: 659.25, t: 0.1 },  // E5
      { f: 783.99, t: 0.2 },  // G5
      { f: 1046.50, t: 0.3 }, // C6
      { f: 1318.51, t: 0.45 } // E6
    ];

    notes.forEach(note => {
      const osc = this.ctx!.createOscillator();
      const gain = this.ctx!.createGain();
      osc.type = 'square';
      osc.frequency.setValueAtTime(note.f, now + note.t);
      gain.gain.setValueAtTime(0.05, now + note.t);
      gain.gain.exponentialRampToValueAtTime(0.001, now + note.t + 0.5);
      osc.connect(gain);
      gain.connect(this.ctx!.destination);
      osc.start(now + note.t);
      osc.stop(now + note.t + 0.5);
    });
  }

  playFlyoutSnap() {
    this.init();
    const now = this.ctx!.currentTime;
    const osc = this.ctx!.createOscillator();
    const gain = this.ctx!.createGain();
    osc.type = 'triangle';
    osc.frequency.setValueAtTime(1200, now);
    osc.frequency.exponentialRampToValueAtTime(800, now + 0.05);
    gain.gain.setValueAtTime(0.05, now);
    gain.gain.exponentialRampToValueAtTime(0.001, now + 0.05);
    osc.connect(gain);
    gain.connect(this.ctx!.destination);
    osc.start(now);
    osc.stop(now + 0.05);
  }

  playWeaponArm() {
    this.init();
    const now = this.ctx!.currentTime;
    const osc = this.ctx!.createOscillator();
    const gain = this.ctx!.createGain();
    osc.type = 'square';
    osc.frequency.setValueAtTime(80, now);
    osc.frequency.linearRampToValueAtTime(40, now + 0.1);
    gain.gain.setValueAtTime(0.1, now);
    gain.gain.exponentialRampToValueAtTime(0.001, now + 0.2);
    osc.connect(gain);
    gain.connect(this.ctx!.destination);
    osc.start(now);
    osc.stop(now + 0.2);
  }

  playSurgeArc() {
    this.init();
    const now = this.ctx!.currentTime;
    const osc = this.ctx!.createOscillator();
    const gain = this.ctx!.createGain();
    osc.type = 'sawtooth';
    osc.frequency.setValueAtTime(60, now);
    osc.frequency.exponentialRampToValueAtTime(240, now + 1.5);
    gain.gain.setValueAtTime(0, now);
    gain.gain.linearRampToValueAtTime(0.05, now + 0.1);
    gain.gain.exponentialRampToValueAtTime(0.001, now + 1.5);
    osc.connect(gain);
    gain.connect(this.ctx!.destination);
    osc.start(now);
    osc.stop(now + 1.5);
  }
}

export const audioService = new AudioService();


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
    osc.start();
    osc.stop(this.ctx!.currentTime + 0.3);
  }

  playScaleNote(index: number) {
    this.init();
    const osc = this.ctx!.createOscillator();
    const gain = this.ctx!.createGain();

    // C Major Scale frequencies (C4 to C5)
    // Do, Re, Mi, Fa, Sol, La, Ti, Do
    const scale = [
      261.63, // C4
      293.66, // D4
      329.63, // E4
      349.23, // F4
      392.00, // G4
      440.00, // A4
      493.88, // B4
      523.25  // C5
    ];

    const noteIndex = index % scale.length;
    const freq = scale[noteIndex];

    osc.type = 'triangle'; // Softer, more flute-like for the scale
    osc.frequency.setValueAtTime(freq, this.ctx!.currentTime);

    // Envelope for a clean "ding"
    gain.gain.setValueAtTime(0, this.ctx!.currentTime);
    gain.gain.linearRampToValueAtTime(0.1, this.ctx!.currentTime + 0.05);
    gain.gain.exponentialRampToValueAtTime(0.001, this.ctx!.currentTime + 0.5);

    osc.connect(gain);
    gain.connect(this.ctx!.destination);

    osc.start();
    osc.stop(this.ctx!.currentTime + 0.5);
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
}

export const audioService = new AudioService();

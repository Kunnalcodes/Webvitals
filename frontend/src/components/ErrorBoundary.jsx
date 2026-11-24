import React from 'react';
import { AlertTriangle, RefreshCw, ShieldAlert } from 'lucide-react';

export class ErrorBoundary extends React.Component {
  constructor(props) {
    super(props);
    this.state = { hasError: false, error: null, errorInfo: null };
  }

  static getDerivedStateFromError(error) {
    return { hasError: true, error };
  }

  componentDidCatch(error, errorInfo) {
    console.error('[WebVitals ErrorBoundary caught an error]:', error, errorInfo);
    this.setState({ errorInfo });
    if (this.props.onError) {
      this.props.onError(error, errorInfo);
    }
  }

  handleReset = () => {
    this.setState({ hasError: false, error: null, errorInfo: null });
    if (this.props.onReset) {
      this.props.onReset();
    }
  };

  render() {
    if (this.state.hasError) {
      if (this.props.fallback) {
        return this.props.fallback;
      }

      return (
        <div className="bg-[#fffdf7] border-2 border-black rounded-2xl p-6 md:p-8 brutal-shadow my-4 space-y-4">
          <div className="flex items-center gap-3 border-b-2 border-black/10 pb-4">
            <div className="p-2.5 bg-rose-100 border border-rose-400 rounded-xl">
              <ShieldAlert className="w-6 h-6 text-rose-700 stroke-[2.2]" />
            </div>
            <div>
              <span className="text-[10px] font-space font-bold uppercase tracking-widest text-rose-700 block mb-0.5">
                Fault Isolation Active
              </span>
              <h4 className="text-xl font-bold font-space text-black">
                {this.props.title || 'Component Rendering Safeguard'}
              </h4>
            </div>
          </div>

          <p className="text-sm font-medium text-zinc-700 font-space leading-relaxed">
            {this.props.message ||
              'A non-critical rendering discrepancy occurred in this intelligence panel. The remainder of your audit data remains intact and secure.'}
          </p>

          {this.state.error && (
            <div className="bg-zinc-950 text-zinc-200 rounded-lg p-3.5 font-mono text-xs border border-black overflow-x-auto">
              <p className="text-rose-400 font-bold mb-1">
                {this.state.error.name}: {this.state.error.message}
              </p>
            </div>
          )}

          <div className="pt-2 flex items-center justify-between">
            <button
              onClick={this.handleReset}
              className="inline-flex items-center gap-2 px-4 py-2 bg-black text-white rounded-lg text-xs font-bold font-space border-2 border-black hover:bg-zinc-800 cursor-pointer transition-colors brutal-shadow-sm"
            >
              <RefreshCw className="w-3.5 h-3.5" />
              <span>Retry Render</span>
            </button>
            <span className="text-[11px] font-mono text-zinc-500">
              WebVitals 4.0 Fault Shield
            </span>
          </div>
        </div>
      );
    }

    return this.props.children;
  }
}

export default ErrorBoundary;

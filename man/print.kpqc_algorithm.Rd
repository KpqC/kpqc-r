\name{print.kpqc_algorithm}
\alias{print.kpqc_algorithm}
\alias{print.kpqc_key_pair}
\alias{print.kpqc_encapsulated_secret}
\title{Print KpqC Objects}
\usage{
\method{print}{kpqc_algorithm}(x, ...)

\method{print}{kpqc_key_pair}(x, ...)

\method{print}{kpqc_encapsulated_secret}(x, ...)
}
\arguments{
  \item{x}{A KpqC algorithm or result object.}
  \item{...}{Additional arguments, currently ignored.}
}
\description{
Print compact summaries without displaying secret key or shared-secret bytes.
}
\value{The input object, invisibly.}
